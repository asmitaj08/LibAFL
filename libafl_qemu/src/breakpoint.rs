use std::{
    borrow::Borrow,
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
};

use crate::{
    emu::{Command, Emulator},
    GuestAddr, IsEmuExitHandler,
};

// TODO: distinguish breakpoints with IDs instead of addresses to avoid collisions.
#[derive(Debug, Clone)]
pub struct Breakpoint {
    addr: GuestAddr,
    cmd: Option<Command>,
    disable_on_trigger: bool,
    enabled: bool,
}

impl Hash for Breakpoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
    }
}

impl PartialEq for Breakpoint {
    fn eq(&self, other: &Self) -> bool {
        self.addr.eq(&other.addr)
    }
}

impl Eq for Breakpoint {}

impl Display for Breakpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Breakpoint @vaddr 0x{:x}", self.addr)
    }
}

impl Borrow<GuestAddr> for Breakpoint {
    fn borrow(&self) -> &GuestAddr {
        &self.addr
    }
}

impl Breakpoint {
    // Emu will return with the breakpoint as exit reason.
    #[must_use]
    pub fn without_command(addr: GuestAddr, disable_on_trigger: bool) -> Self {
        Self {
            addr,
            cmd: None,
            disable_on_trigger,
            enabled: false,
        }
    }

    // Emu will execute the command when it meets the breakpoint.
    #[must_use]
    pub fn with_command(addr: GuestAddr, cmd: Command, disable_on_trigger: bool) -> Self {
        Self {
            addr,
            cmd: Some(cmd),
            disable_on_trigger,
            enabled: false,
        }
    }

    #[must_use]
    pub fn addr(&self) -> GuestAddr {
        self.addr
    }

    pub fn enable<E: IsEmuExitHandler>(&mut self, emu: &Emulator<E>) {
        if !self.enabled {
            emu.set_breakpoint_addr(self.addr);
            self.enabled = true;
        }
    }

    pub fn disable<E: IsEmuExitHandler>(&mut self, emu: &Emulator<E>) {
        if self.enabled {
            emu.unset_breakpoint_addr(self.addr.into());
            self.enabled = false;
        }
    }

    pub fn trigger<E: IsEmuExitHandler>(&mut self, emu: &Emulator<E>) -> Option<&Command> {
        if self.disable_on_trigger {
            self.disable(emu);
        }

        self.cmd.as_ref()
    }
}
