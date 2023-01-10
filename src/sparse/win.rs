/// Windows specific sparse file functions
use std::path::Path;
use std::fs::File;
use widestring::U16String;
use std::os::windows::io::AsRawHandle;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    FILE_ZERO_DATA_INFORMATION,
    FSCTL_SET_SPARSE,
    FSCTL_SET_ZERO_DATA,
};
use windows::{
    core::*,
    core::Result,
    Win32::Storage::FileSystem::*
};


/// Initialize a sparse data run
pub fn set_sparse_run(file: &mut File, offset: i64, length: i64) -> Result<()> {
    let handle = HANDLE(file.as_raw_handle() as isize);
    let end_offset = match offset.checked_add(length) {
        Some(o) => o,
        None => panic!("end offset calcuation overflow!")
    };

    let zero_data_info = FILE_ZERO_DATA_INFORMATION {
        FileOffset: offset,
        BeyondFinalZero: end_offset
    };
    let zero_data_size: u32 = std::mem::size_of::<FILE_ZERO_DATA_INFORMATION>()
        .try_into()
        .expect("Could not convert size of FILE_ZERO_DATA_INFORMATION into u32.");
    let zero_data_info_ptr = &zero_data_info as *const _ as *const std::ffi::c_void;

    let result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_ZERO_DATA,
            Some(zero_data_info_ptr),
            zero_data_size,
            None,
            0,
            None,
            None
        )
    };

    if !result.as_bool() {
        return Err(
            unsafe{GetLastError().into()}
        );
    }

    Ok(())
}


/// Mark a File as sparse
pub fn make_file_sparse(file: &mut File) -> Result<()> {
    let handle = HANDLE(file.as_raw_handle() as isize);
    let result = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_SPARSE,
            None,
            0,
            None,
            0,
            None,
            None
        )
    };

    if !result.as_bool() {
        return Err(
            unsafe{GetLastError().into()}
        );
    }

    Ok(())
}


/// Check if a volume path supports sparse file
pub fn supports_sparse(path: impl AsRef<Path>) -> Result<bool> {
    let path = path.as_ref();
    let wstr = U16String::from_os_str(path.as_os_str());
    let wstr = PCWSTR::from_raw(wstr.as_ptr());

    let mut flags = 0;

    let result = unsafe {
        GetVolumeInformationW(
            wstr,
            None,
            None,
            None,
            Some(&mut flags),
            None
        )
    };

    if !result.as_bool() {
        return Err(
            unsafe{GetLastError().into()}
        );
    }

    if flags & 0x00000040 == 0x00000040 {
        return Ok(true)
    }

    Ok(false)
}