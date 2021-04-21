use crate::context::*;
use crate::{MinidumpMemory, MinidumpModuleList, MinidumpThread, Module};
use scroll::Pread;

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub start_of_frame: u64,
    pub end_of_frame: u64,
    pub instruction: u64,
    pub trust: Trust,
    pub module_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    Context,
    Cfi,
    FramePointer,
    Scan,
}

pub fn walkies(
    context: &MinidumpContext,
    stack_memory: &MinidumpMemory,
    modules: &MinidumpModuleList,
) -> Vec<StackFrame> {
    let mut stack = Vec::new();

    // TODO: validation on this?
    stack.push(StackFrame {
        start_of_frame: context.get_frame_pointer(),
        end_of_frame: context.get_stack_pointer(),
        instruction: context.get_instruction_pointer(),
        trust: Trust::Context,
        module_name: String::new(),
    });

    loop {
        // Successively try to get the next frame with increasingly hack methods.
        // If no method works, then assume we've reached the end of the stack.
        let current_frame = stack.last().unwrap();
        if let Ok(frame) = get_next_frame_via_cfi(current_frame, context, stack_memory, modules) {
            stack.push(frame);
            continue;
        }
        if let Ok(frame) =
            get_next_frame_via_frame_pointer(current_frame, context, stack_memory, modules)
        {
            stack.push(frame);
            continue;
        }
        if let Ok(frame) = get_next_frame_via_scan(current_frame, context, stack_memory, modules) {
            stack.push(frame);
            continue;
        }
        
        break;
    }

    for frame in &mut stack {
        if let Some(module) = modules.module_at_address(frame.instruction) {
            frame.module_name = module.code_file().to_owned().to_string(); 
        }
    }

    // We can't walk the stack anymore, do some post-processing

    stack
}

fn get_next_frame_via_cfi(
    _current_frame: &StackFrame,
    _context: &MinidumpContext,
    _stack: &MinidumpMemory,
    _modules: &MinidumpModuleList,
) -> Result<StackFrame, ()> {
    // unimplemented
    Err(())
}

fn get_next_frame_via_frame_pointer(
    current_frame: &StackFrame,
    context: &MinidumpContext,
    stack: &MinidumpMemory,
    _modules: &MinidumpModuleList,
) -> Result<StackFrame, ()> {
    let StackFrame { start_of_frame, .. } = *current_frame;

    let stack_mem_base = stack.base_address;
    let stack_mem_size = stack.size;
    let stack_base_frame = stack_mem_base + stack_mem_size;

    let is_64bit = context.is_64bit();
    let ptr_width = if is_64bit { 8 } else { 4 };

    let frame_offset = (start_of_frame - stack_mem_base) as usize;

    let rbp: u64 = pread_ptr(&stack.bytes, frame_offset, is_64bit)?;
    let rip: u64 = pread_ptr(&stack.bytes, frame_offset + ptr_width as usize, is_64bit)?;

    // Validation of new start_of_frame:
    // * Must not be after (before in memory) this frame's start
    // * Must not be before (after in memory) the start of the stack
    // * Must be aligned to a pointer
    if start_of_frame <= rbp && rbp <= stack_base_frame && rbp % ptr_width == 0 {
        Ok(StackFrame {
            start_of_frame: rbp,
            end_of_frame: rbp + ptr_width * 2,
            instruction: rip, // TODO?: validate this
            trust: Trust::FramePointer,
            module_name: String::new(),
        })
    } else {
        Err(())
    }
}

fn get_next_frame_via_scan(
    current_frame: &StackFrame,
    context: &MinidumpContext,
    stack: &MinidumpMemory,
    modules: &MinidumpModuleList,
) -> Result<StackFrame, ()> {
    // Stack scanning is just walking from the end of the frame until we encounter
    // a value on the stack that looks like a pointer into some code (it's an address
    // in a range covered by one of our modules). If we find such an instruction,
    // we assume it's a rip value that was pushed by the CALL instruction that created
    // the current frame. The next frame is then assumed to end just before that
    // rip value.
    let default_scan_range = 40;
    let extended_scan_range = default_scan_range * 4;

    let scan_range = if let Trust::Context = current_frame.trust {
        extended_scan_range
    } else {
        default_scan_range
    };

    let is_64bit = context.is_64bit();
    let ptr_width = if is_64bit { 8 } else { 4 };
    let stack_mem_base = stack.base_address;
    let stack_mem_size = stack.size;
    let stack_base_frame = stack_mem_base + stack_mem_size;

    // TODO: pointer-align this..? Does CALL push aligned rip values? Is rsp aligned?
    let start = current_frame.end_of_frame;

    for i in 0..scan_range {
        let address_of_rip = start - stack_mem_base + i * ptr_width;
        let rip: u64 = pread_ptr(&stack.bytes, address_of_rip as usize, is_64bit)?;
        if instruction_is_valid(rip, modules) {
            // rip is pushed by CALL, so rsp is just address_of_rip + 8
            let rsp = address_of_rip + ptr_width;

            // Try to restore rbp as well. This can be possible in two cases:
            //
            // 1. This function has the standard prologue that pushes rbp and
            //    sets rbp = rsp. If this is the case, then the current rbp should be
            //    immediately after (before in memory) address_of_rip.
            //
            // 2. This function does not use rbp, and has just preserved it
            //    from the caller. If this is the case, rbp should be before
            //    (after in memory) address_of_rip.

            // TODO: Should really be an invalid value but let's use this for now.
            let mut rbp = stack_base_frame;

            let address_of_rbp = address_of_rip - ptr_width;
            if current_frame.start_of_frame == address_of_rbp {
                let potential_rbp = pread_ptr(&stack.bytes, address_of_rbp as usize, is_64bit)?;
                if potential_rbp > address_of_rip {
                    rbp = potential_rbp;
                }
            } else if current_frame.start_of_frame >= address_of_rip + ptr_width {
                rbp = current_frame.start_of_frame;
            }

            return Ok(StackFrame {
                start_of_frame: rbp,
                end_of_frame: rsp,
                instruction: rip,
                trust: Trust::Scan,
                module_name: String::new(),
            });
        }
    }

    Err(())
}

fn pread_ptr(bytes: &[u8], offset: usize, is_64bit: bool) -> Result<u64, ()> {
    if is_64bit {
        let val: u64 = bytes
            .pread_with(offset, scroll::Endian::Little)
            .map_err(|_| ())?;
        Ok(val)
    } else {
        let val: u32 = bytes
            .pread_with(offset, scroll::Endian::Little)
            .map_err(|_| ())?;
        Ok(val as u64)
    }
}

fn instruction_is_valid(instruction: u64, modules: &MinidumpModuleList) -> bool {
    if let Some(_module) = modules.module_at_address(instruction) {
        // TODO: if mapped, check if this instruction actually maps to a function line
        true
    } else {
        false
    }
}
