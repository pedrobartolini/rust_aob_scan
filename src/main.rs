use winapi::ctypes::c_void;
use winapi::shared::minwindef::HMODULE;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::EnumProcessModulesEx;
use winapi::um::psapi::GetModuleBaseNameA;
use winapi::um::psapi::GetModuleInformation;
use winapi::um::psapi::LIST_MODULES_ALL;
use winapi::um::psapi::MODULEINFO;
use winapi::um::winnt::HANDLE;
use winapi::um::winnt::PROCESS_ALL_ACCESS;
use winapi::um::winuser::GetWindowThreadProcessId;

mod window;

fn main() -> anyhow::Result<()> {
   let windows = window::get_windows();

   let any_tibia = windows.iter().find(|window| window.title.contains("Untitled - Notepad")).ok_or(anyhow::anyhow!("Nenhuma janela encontrada"))?;

   println!("Cliente -> {}", any_tibia.title);

   let mut pid = 0;

   if unsafe { GetWindowThreadProcessId(any_tibia.hwnd, &mut pid) } == 0 {
      return Err(anyhow::anyhow!("HWND inválido."));
   }

   let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) } as HANDLE;

   let module = get_module(process_handle, "client.exe")?;

   let (module_address, module_size) = get_module_information(process_handle, module)?;

   println!("module_addr: {:?} size: {:?}", module_address, module_size);

   let signature = [0xFF, 0x50, 0x20, 0x8B, 0xCB, 0x66, 0x89, 0x43, 0x24, 0xFF, 0x15, 0x20, 0x60];

   let now = std::time::Instant::now();

   let signature_addr = find_signature_address(process_handle, module_address, module_size, &signature)?;

   println!("elasped micros: {}", now.elapsed().as_micros());

   println!("signature_addr: {:?}", signature_addr);

   Ok(())
}

fn get_module(process_handle: HANDLE, target_name: &str) -> anyhow::Result<HMODULE> {
   unsafe {
      let mut module_handles: [HMODULE; 1024] = [std::ptr::null_mut(); 1024];
      let mut size = 0;

      if EnumProcessModulesEx(process_handle, module_handles.as_mut_ptr(), std::mem::size_of::<[HMODULE; 1024]>().try_into()?, &mut size, LIST_MODULES_ALL) == 0 {
         return Err(anyhow::anyhow!("Falha ao listar modulos do processo."));
      }

      let limit = size as usize / std::mem::size_of::<HMODULE>();
      let mut index = 0;

      while index < limit {
         let mut name_buffer: [i8; 256] = [0; 256];

         if GetModuleBaseNameA(process_handle, module_handles[index], name_buffer.as_mut_ptr(), std::mem::size_of::<[i8; 256]>().try_into()?) == 0 {
            index += 1;
            continue;
         }

         let name_buffer: [u8; 256] = std::mem::transmute(name_buffer);

         let name = String::from_utf8_lossy(&name_buffer).trim_end_matches(char::from(0)).to_string();

         if name != target_name {
            index += 1;
            continue;
         }

         return Ok(module_handles[index]);
      }

      Err(anyhow::anyhow!("Modulo não encontrado."))
   }
}

fn get_module_information(handle: HANDLE, module: HMODULE) -> anyhow::Result<(*mut c_void, u32)> {
   unsafe {
      let mut module_info: MODULEINFO = std::mem::zeroed();

      if GetModuleInformation(handle, module, &mut module_info, std::mem::size_of::<MODULEINFO>().try_into()?) == 0 {
         return Err(anyhow::anyhow!("Falha ao ler informações do modulo."));
      }

      Ok((module_info.lpBaseOfDll, module_info.SizeOfImage))
   }
}

fn find_sig_addr(slice: &[u8], signature: &[u8]) -> Option<usize> {
   for i in 0..=(slice.len() - signature.len()) {
      let mut found = true;

      for j in 0..signature.len() {
         if slice[i + j] != signature[j] {
            found = false;
            break;
         }
      }

      if found {
         return Some(i);
      }
   }

   None
}

fn find_signature_address(handle: HANDLE, module_address: *mut c_void, module_size: u32, signature: &[u8]) -> anyhow::Result<*mut c_void> {
   let mut buffer = [0u8; 4096];
   let mut bytes_read = 0;

   unsafe {
      let mut i: usize = 0;

      while i < module_size as usize {
         if ReadProcessMemory(handle, (module_address as usize + i) as *mut _, buffer.as_mut_ptr() as *mut _, buffer.len(), &mut bytes_read) == 0 {
            return Err(anyhow::anyhow!("Falha ao ler memória do processo."));
         }

         if let Some(sig) = find_sig_addr(&buffer[..bytes_read], &signature) {
            return Ok((module_address as usize + i + sig) as *mut c_void);
         }

         i += bytes_read;
      }
   }

   Err(anyhow::anyhow!("Endereço da assinatura não encontrado."))
}
