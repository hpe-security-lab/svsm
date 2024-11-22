(function() {
    var implementors = Object.fromEntries([["svsm",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"enum\" href=\"svsm/fs/api/enum.FsError.html\" title=\"enum svsm::fs::api::FsError\">FsError</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"enum\" href=\"svsm/insn_decode/decode/enum.CpuMode.html\" title=\"enum svsm::insn_decode::decode::CpuMode\">CpuMode</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"enum\" href=\"svsm/task/tasks/enum.TaskState.html\" title=\"enum svsm::task::tasks::TaskState\">TaskState</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"enum\" href=\"svsm/types/enum.Bytes.html\" title=\"enum svsm::types::Bytes\">Bytes</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/acpi/tables/struct.ACPITableHeader.html\" title=\"struct svsm::acpi::tables::ACPITableHeader\">ACPITableHeader</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/acpi/tables/struct.RSDPDesc.html\" title=\"struct svsm::acpi::tables::RSDPDesc\">RSDPDesc</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/acpi/tables/struct.RawACPITableHeader.html\" title=\"struct svsm::acpi::tables::RawACPITableHeader\">RawACPITableHeader</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/address/struct.PhysAddr.html\" title=\"struct svsm::address::PhysAddr\">PhysAddr</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/address/struct.VirtAddr.html\" title=\"struct svsm::address::VirtAddr\">VirtAddr</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/apic/struct.ApicIcr.html\" title=\"struct svsm::cpu::apic::ApicIcr\">ApicIcr</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/apic/struct.LocalApic.html\" title=\"struct svsm::cpu::apic::LocalApic\">LocalApic</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/gdt/struct.GDT.html\" title=\"struct svsm::cpu::gdt::GDT\">GDT</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/gdt/struct.GDTDesc.html\" title=\"struct svsm::cpu::gdt::GDTDesc\">GDTDesc</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/gdt/struct.GDTEntry.html\" title=\"struct svsm::cpu::gdt::GDTEntry\">GDTEntry</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/idt/common/struct.IDT.html\" title=\"struct svsm::cpu::idt::common::IDT\">IDT</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/idt/common/struct.IdtDesc.html\" title=\"struct svsm::cpu::idt::common::IdtDesc\">IdtDesc</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/idt/common/struct.IdtEntry.html\" title=\"struct svsm::cpu::idt::common::IdtEntry\">IdtEntry</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/idt/common/struct.X86ExceptionContext.html\" title=\"struct svsm::cpu::idt::common::X86ExceptionContext\">X86ExceptionContext</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/irq_state/struct.IrqGuard.html\" title=\"struct svsm::cpu::irq_state::IrqGuard\">IrqGuard</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/irq_state/struct.IrqState.html\" title=\"struct svsm::cpu::irq_state::IrqState\">IrqState</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/isst/struct.Isst.html\" title=\"struct svsm::cpu::isst::Isst\">Isst</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/percpu/struct.GuestVmsaRef.html\" title=\"struct svsm::cpu::percpu::GuestVmsaRef\">GuestVmsaRef</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/registers/struct.X86GeneralRegs.html\" title=\"struct svsm::cpu::registers::X86GeneralRegs\">X86GeneralRegs</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/registers/struct.X86InterruptFrame.html\" title=\"struct svsm::cpu::registers::X86InterruptFrame\">X86InterruptFrame</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/registers/struct.X86SegmentRegs.html\" title=\"struct svsm::cpu::registers::X86SegmentRegs\">X86SegmentRegs</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/cpu/tss/struct.X86Tss.html\" title=\"struct svsm::cpu::tss::X86Tss\">X86Tss</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/debug/stacktrace/struct.StackFrame.html\" title=\"struct svsm::debug::stacktrace::StackFrame\">StackFrame</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/fs/ramfs/struct.RawRamFile.html\" title=\"struct svsm::fs::ramfs::RawRamFile\">RawRamFile</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/fw_meta/struct.SevFWMetaData.html\" title=\"struct svsm::fw_meta::SevFWMetaData\">SevFWMetaData</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/greq/msg/struct.SnpGuestRequestMsgHdr.html\" title=\"struct svsm::greq::msg::SnpGuestRequestMsgHdr\">SnpGuestRequestMsgHdr</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/insn_decode/decode/struct.DecodedInsnCtx.html\" title=\"struct svsm::insn_decode::decode::DecodedInsnCtx\">DecodedInsnCtx</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/insn_decode/decode/struct.InsnBytes.html\" title=\"struct svsm::insn_decode::decode::InsnBytes\">InsnBytes</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/insn_decode/decode/struct.ModRM.html\" title=\"struct svsm::insn_decode::decode::ModRM\">ModRM</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/insn_decode/decode/struct.PrefixFlags.html\" title=\"struct svsm::insn_decode::decode::PrefixFlags\">PrefixFlags</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/insn_decode/decode/struct.RexPrefix.html\" title=\"struct svsm::insn_decode::decode::RexPrefix\">RexPrefix</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/insn_decode/decode/struct.Sib.html\" title=\"struct svsm::insn_decode::decode::Sib\">Sib</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/insn_decode/insn/struct.Instruction.html\" title=\"struct svsm::insn_decode::insn::Instruction\">Instruction</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/insn_decode/opcode/struct.OpCodeFlags.html\" title=\"struct svsm::insn_decode::opcode::OpCodeFlags\">OpCodeFlags</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/io/struct.DefaultIOPort.html\" title=\"struct svsm::io::DefaultIOPort\">DefaultIOPort</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/locking/common/struct.IrqSafeLocking.html\" title=\"struct svsm::locking::common::IrqSafeLocking\">IrqSafeLocking</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/locking/common/struct.IrqUnsafeLocking.html\" title=\"struct svsm::locking::common::IrqUnsafeLocking\">IrqUnsafeLocking</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/alloc/struct.MemInfo.html\" title=\"struct svsm::mm::alloc::MemInfo\">MemInfo</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/alloc/struct.MemoryRegion.html\" title=\"struct svsm::mm::alloc::MemoryRegion\">MemoryRegion</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/alloc/struct.SvsmAllocator.html\" title=\"struct svsm::mm::alloc::SvsmAllocator\">SvsmAllocator</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/pagetable/struct.PTEntry.html\" title=\"struct svsm::mm::pagetable::PTEntry\">PTEntry</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/pagetable/struct.PTEntryFlags.html\" title=\"struct svsm::mm::pagetable::PTEntryFlags\">PTEntryFlags</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/pagetable/struct.PTPage.html\" title=\"struct svsm::mm::pagetable::PTPage\">PTPage</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/pagetable/struct.PageTable.html\" title=\"struct svsm::mm::pagetable::PageTable\">PageTable</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/pagetable/struct.RawPageTablePart.html\" title=\"struct svsm::mm::pagetable::RawPageTablePart\">RawPageTablePart</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/virtualrange/struct.VirtualRange.html\" title=\"struct svsm::mm::virtualrange::VirtualRange\">VirtualRange</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/vm/mapping/api/struct.VMMAdapter.html\" title=\"struct svsm::mm::vm::mapping::api::VMMAdapter\">VMMAdapter</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/vm/mapping/kernel_stack/struct.VMKernelStack.html\" title=\"struct svsm::mm::vm::mapping::kernel_stack::VMKernelStack\">VMKernelStack</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/vm/mapping/phys_mem/struct.VMPhysMem.html\" title=\"struct svsm::mm::vm::mapping::phys_mem::VMPhysMem\">VMPhysMem</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/vm/mapping/rawalloc/struct.RawAllocMapping.html\" title=\"struct svsm::mm::vm::mapping::rawalloc::RawAllocMapping\">RawAllocMapping</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/vm/mapping/reserved/struct.VMReserved.html\" title=\"struct svsm::mm::vm::mapping::reserved::VMReserved\">VMReserved</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/vm/mapping/vmalloc/struct.VMalloc.html\" title=\"struct svsm::mm::vm::mapping::vmalloc::VMalloc\">VMalloc</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/platform/native/struct.NativePlatform.html\" title=\"struct svsm::platform::native::NativePlatform\">NativePlatform</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/platform/snp/struct.GHCBIOPort.html\" title=\"struct svsm::platform::snp::GHCBIOPort\">GHCBIOPort</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/platform/snp/struct.SnpPlatform.html\" title=\"struct svsm::platform::snp::SnpPlatform\">SnpPlatform</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/platform/tdp/struct.GHCIIOPort.html\" title=\"struct svsm::platform::tdp::GHCIIOPort\">GHCIIOPort</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/platform/tdp/struct.TdpPlatform.html\" title=\"struct svsm::platform::tdp::TdpPlatform\">TdpPlatform</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/protocols/struct.RequestParams.html\" title=\"struct svsm::protocols::RequestParams\">RequestParams</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/sev/ghcb/struct.PageStateChangeHeader.html\" title=\"struct svsm::sev::ghcb::PageStateChangeHeader\">PageStateChangeHeader</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/sev/hv_doorbell/struct.HVDoorbellFlags.html\" title=\"struct svsm::sev::hv_doorbell::HVDoorbellFlags\">HVDoorbellFlags</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/sev/hv_doorbell/struct.HVExtIntStatus.html\" title=\"struct svsm::sev::hv_doorbell::HVExtIntStatus\">HVExtIntStatus</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/sev/secrets_page/struct.SecretsPage.html\" title=\"struct svsm::sev::secrets_page::SecretsPage\">SecretsPage</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/task/schedule/struct.RunQueue.html\" title=\"struct svsm::task::schedule::RunQueue\">RunQueue</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/task/schedule/struct.TaskList.html\" title=\"struct svsm::task::schedule::TaskList\">TaskList</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/task/tasks/struct.TaskContext.html\" title=\"struct svsm::task::tasks::TaskContext\">TaskContext</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/task/tasks/struct.TaskIDAllocator.html\" title=\"struct svsm::task::tasks::TaskIDAllocator\">TaskIDAllocator</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/task/tasks/struct.TaskListAdapter.html\" title=\"struct svsm::task::tasks::TaskListAdapter\">TaskListAdapter</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/task/tasks/struct.TaskRunListAdapter.html\" title=\"struct svsm::task::tasks::TaskRunListAdapter\">TaskRunListAdapter</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/task/waiting/struct.WaitQueue.html\" title=\"struct svsm::task::waiting::WaitQueue\">WaitQueue</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/tdx/tdcall/struct.EptMappingInfo.html\" title=\"struct svsm::tdx::tdcall::EptMappingInfo\">EptMappingInfo</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocator64.html\" title=\"struct svsm::utils::bitmap_allocator::BitmapAllocator64\">BitmapAllocator64</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/vtpm/tcgtpm/struct.TcgTpm.html\" title=\"struct svsm::vtpm::tcgtpm::TcgTpm\">TcgTpm</a>"],["impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"svsm/utils/bitmap_allocator/trait.BitmapAllocator.html\" title=\"trait svsm::utils::bitmap_allocator::BitmapAllocator\">BitmapAllocator</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/utils/bitmap_allocator/struct.BitmapAllocatorTree.html\" title=\"struct svsm::utils::bitmap_allocator::BitmapAllocatorTree\">BitmapAllocatorTree</a>&lt;T&gt;"],["impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>, I: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/locking/spinlock/struct.RawSpinLock.html\" title=\"struct svsm::locking::spinlock::RawSpinLock\">RawSpinLock</a>&lt;T, I&gt;"],["impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.u16.html\">u16</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/alloc/struct.Slab.html\" title=\"struct svsm::mm::alloc::Slab\">Slab</a>&lt;N&gt;"],["impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.u16.html\">u16</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/alloc/struct.SlabCommon.html\" title=\"struct svsm::mm::alloc::SlabCommon\">SlabCommon</a>&lt;N&gt;"],["impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.u16.html\">u16</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/mm/alloc/struct.SlabPage.html\" title=\"struct svsm::mm::alloc::SlabPage\">SlabPage</a>&lt;N&gt;"],["impl&lt;const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"svsm/string/struct.FixedString.html\" title=\"struct svsm::string::FixedString\">FixedString</a>&lt;N&gt;"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[25389]}