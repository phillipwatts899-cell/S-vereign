#![allow(non_camel_case_types)]

use std::ffi::c_void;
use std::ptr;
use libc::c_int;

// Map standard JNI types explicitly
pub type jint = c_int;
pub type jlong = i64;
pub type jobject = *mut c_void;

// Fixed: Paths map directly to your local flat src/ folder structure
use crate::locked_buffer::LockedBuffer;

/// Native buffer allocation wrapper. Exposes a hook to the JVM to pin
/// raw memory layouts completely independent of the GC tracking loop.
extern "C" fn native_allocate_buffer(_env: *mut c_void, _class: jobject, size: jint) -> jlong {
    if size <= 0 { return 0; }
    
    match LockedBuffer::new(size as usize) {
        Ok(buffer) => {
            let boxed = Box::new(buffer);
            Box::into_raw(boxed) as jlong
        }
        Err(_) => 0,
    }
}

/// Native buffer destructor loop. Re-takes pointer context and drops it
/// safely to trigger structural zeroing of key remnants.
extern "C" fn native_free_buffer(_env: *mut c_void, _class: jobject, ptr: jlong) {
    if ptr == 0 { return; }
    unsafe {
        let _to_drop = Box::from_raw(ptr as *mut LockedBuffer);
    }
}

#[repr(C)]
struct JNINativeMethod {
    name: *const u8,
    signature: *const u8,
    fn_ptr: *const c_void,
}

/// The authoritative entry-point called dynamically by Android runtime
/// systems upon execution of System.loadLibrary().
#[no_mangle]
pub unsafe extern "C" fn JNI_OnLoad(vm: *mut c_void, _reserved: *mut c_void) -> jint {
    const JNI_VERSION_1_6: jint = 0x00010006;
    
    let mut env: *mut c_void = ptr::null_mut();
    let vm_ptr = vm as *mut *mut fn(*mut c_void, *mut *mut c_void, jint) -> jint;
    
    if unsafe { (**vm_ptr)(vm, &mut env, JNI_VERSION_1_6) } != 0 {
        return -1;
    }

    let class_name = b"com/sovereigncore/otp/NativeBridge\0";
    let methods = [
        JNINativeMethod {
            name: b"allocateLockedBuffer\0".as_ptr(),
            signature: b"(I)J\0".as_ptr(),
            fn_ptr: native_allocate_buffer as *const c_void,
        },
        JNINativeMethod {
            name: b"freeLockedBuffer\0".as_ptr(),
            signature: b"(J)V\0".as_ptr(),
            fn_ptr: native_free_buffer as *const c_void,
        },
    ];

    let env_ptr = env as *mut *mut fn(*mut c_void, *const u8) -> jobject;
    let find_class = unsafe { (**env_ptr)(env, class_name.as_ptr()) };
    if find_class.is_null() {
        return -1;
    }

    // Exact pointer-offset binding targeting RegisterNatives inside the virtual JNI table map
    let register_natives = *((env_ptr as *mut usize).add(215)) as *mut fn(*mut c_void, jobject, *const JNINativeMethod, jint) -> jint;
    if unsafe { (*register_natives)(env, find_class, methods.as_ptr(), methods.len() as jint) } < 0 {
        return -1;
    }

    JNI_VERSION_1_6
}

