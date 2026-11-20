//! Phase 7C only: disposable allocator, no Android service or task-profile changes.
#[allow(dead_code)]
#[path = "../guest/cgroup/memory.rs"]
pub(crate) mod memory_cgroup;
#[allow(dead_code)]
#[path = "../guest/process/supervision.rs"]
pub(crate) mod supervision;
#[allow(dead_code)]
#[path = "../diagnostics/zygote.rs"]
pub(crate) mod zygote;
mod diagnostics {
    pub(crate) use crate::zygote;
}

mod guest {
    pub(crate) use crate::memory_cgroup as cgroup;

    pub(crate) mod process {
        pub(crate) use crate::supervision;
    }
}

#[path = "../diagnostics/memory.rs"]
mod memory;

fn main() -> std::io::Result<()> {
    memory::entrypoint()
}
