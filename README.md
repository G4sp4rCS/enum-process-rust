# enum-process-rust

En este repositorio se encuentra un ejemplo de cómo enumerar los procesos en ejecución en un sistema operativo Windows utilizando Rust como alternativa a C/C++.

## Descripción

Este proyecto demuestra dos técnicas principales para trabajar con procesos en Windows:

1. **Enumeración de todos los procesos del sistema** - Lista todos los procesos activos con sus PIDs y nombres
2. **Búsqueda de un proceso específico** - Encuentra un proceso por nombre y obtiene su handle

## Dependencias

El proyecto utiliza el crate `windows-sys` que proporciona bindings directos a la API de Windows:

```toml
[dependencies]
windows-sys = { version = "0.48.0", features = [
    "Win32_Foundation",
    "Win32_System_ProcessStatus", 
    "Win32_System_Threading",
    "Win32_System_LibraryLoader"
] }
```

Las features habilitadas nos dan acceso a las APIs necesarias:
- `Win32_Foundation`: Tipos básicos como `HANDLE`, `HMODULE` que sirven para manejar recursos de Windows tales como procesos y módulos
- `Win32_System_ProcessStatus`: Funciones `EnumProcesses`, `EnumProcessModules`, `GetModuleBaseNameW`
- `Win32_System_Threading`: Función `OpenProcess` y constantes de permisos
- `Win32_System_LibraryLoader`: Manejo de módulos

- Un handle en Windows es una referencia a un recurso del sistema, como un proceso o un archivo. Se utiliza para interactuar con ese recurso a través de la API de Windows.

## Cómo funciona

### 1. Enumeración de procesos (`PrintProcesses`)

#### Paso 1: Obtener lista de PIDs
```rust
let mut processes: [u32; MAX_PROCESSES] = [0; MAX_PROCESSES];
let mut bytes_returned: u32 = 0;

if EnumProcesses(
    processes.as_mut_ptr(),
    (processes.len() * std::mem::size_of::<u32>()) as u32,
    &mut bytes_returned,
) == 0 {
    eprintln!("[!] EnumProcesses Failed With Error : {}", GetLastError());
    return false;
}
```

- `EnumProcesses` llena un array con todos los PIDs (Process IDs) activos del sistema
- `bytes_returned` nos dice cuántos bytes se escribieron, lo que permite calcular el número de procesos

#### Paso 2: Calcular número de procesos
```rust
let num_processes = (bytes_returned as usize) / std::mem::size_of::<u32>();
```

- Dividimos los bytes retornados por el tamaño de un `u32` para obtener la cantidad de procesos

#### Paso 3: Iterar por cada proceso
```rust
for i in 0..num_processes {
    let pid = processes[i];
    
    if pid != 0 {
        let h_process: HANDLE = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0, // FALSE
            pid,
        );
```

- `OpenProcess` abre un handle al proceso con permisos específicos:
  - `PROCESS_QUERY_INFORMATION`: Permite consultar información del proceso
  - `PROCESS_VM_READ`: Permite leer la memoria virtual del proceso
  - usamos el pipe `|` para combinar permisos, significa "o" bit a bit "or bitwise"

#### Paso 4: Obtener información del módulo principal
```rust
let mut h_module: HMODULE = 0;
let mut bytes_needed: u32 = 0;

if EnumProcessModules(
    h_process,
    &mut h_module,
    std::mem::size_of::<HMODULE>() as u32,
    &mut bytes_needed,
) == 0 {
    // Manejo de error
}
```

- `EnumProcessModules` obtiene el primer módulo (ejecutable principal) del proceso
- Necesitamos el handle del módulo para obtener su nombre

#### Paso 5: Obtener el nombre del proceso
```rust
let mut process_name: [u16; MAX_PATH] = [0; MAX_PATH];

if GetModuleBaseNameW(
    h_process,
    h_module,
    process_name.as_mut_ptr(),
    MAX_PATH as u32,
) == 0 {
    // Manejo de error
} else {
    let name_len = process_name.iter().position(|&x| x == 0).unwrap_or(MAX_PATH);
    let name = String::from_utf16_lossy(&process_name[..name_len]);
    println!("[{:03}] Process \"{}\" - Of Pid : {}", i, name, pid);
}
```

- `GetModuleBaseNameW` obtiene el nombre del módulo en formato UTF-16
- Convertimos de UTF-16 a String de Rust para mostrar el resultado
- El nombre se guarda en un array de `u16` (caracteres UTF-16)

#### Paso 6: Limpiar recursos
```rust
CloseHandle(h_process);
```

- Importante cerrar el handle del proceso para liberar recursos del sistema

### 2. Búsqueda de proceso específico (`GetRemoteProcessHandle`)

Esta función es similar a `PrintProcesses` pero con lógica adicional para encontrar un proceso específico:

#### Comparación de nombres
```rust
let target_name_utf16: Vec<u16> = process_name.encode_utf16().collect();

// Dentro del loop:
if name_len == target_name_utf16.len() 
    && process_name_buf[..name_len] == target_name_utf16[..] 
{
    let name = String::from_utf16_lossy(&process_name_buf[..name_len]);
    println!("[+] FOUND \"{}\" - Of Pid : {}", name, pid);
    return Some((pid, h_process));
}
```

- Convierte el nombre objetivo a UTF-16 para comparación directa
- Compara tanto la longitud como el contenido del nombre
- Retorna el PID y handle si encuentra coincidencia

### 3. Uso en `main`

```rust
fn main() {
    if PrintProcesses() {
        println!("Process enumeration completed successfully.");
        
        if let Some((pid, handle)) = GetRemoteProcessHandle("Explorer.EXE") {
            println!("Found explorer.exe with PID: {} and handle: {:?}", pid, handle);
            unsafe { CloseHandle(handle) };
        } else {
            println!("explorer.exe not found.");
        }
    } else {
        println!("Process enumeration failed.");
    }
}
```

- Primero enumera todos los procesos
- Luego busca específicamente el proceso "Explorer.EXE"
- Siempre cierra los handles obtenidos

## Compilación y ejecución

```bash
cargo build
cargo run
```

## Compilación si estamos en GNU/Linux con `mingw-w64`

```bash
cargo build --target x86_64-pc-windows-gnu
```

## Salida esperada

```
[i] Number Of Processes Detected : 277
[059] Process "wallpaper32.exe" - Of Pid : 5260
[060] Process "svchost.exe" - Of Pid : 5344
...
[+] FOUND "Explorer.EXE" - Of Pid : 6592
Found explorer.exe with PID: 6592 and handle: 140735598988288
Process enumeration completed successfully.
```

