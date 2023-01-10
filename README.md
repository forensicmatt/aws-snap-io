# aws-snap-io
Library for implementing Read/Seek for AWS snapshots. The library does not currently offer asnyc
read/seek implementation nor does it use parallel means for reading multiple blocks during any
given read. A sparse caching layer can be used so that multiple reads do not download a 
block more than once.

Supported FS:
|OS|Note|
|---|---|
|Windows|Cache uses DeviceIoControl::FSCTL_SET_SPARSE and FSCTL_SET_ZERO_DATA|
|Linux|Just uses lseek (if FS does not support sparse, then cache will not be sparse.|

Use [Coldsnap](https://github.com/awslabs/coldsnap) for copying entire snapshots via parallel means.


# read_snapshot
```
Test tool to read a number of bytes from a given offset in a snapshot. This requires that you have already setup your AWS credentials and region. This application is for testing and example only. Note this tool/lib does not support concurrent reads from a snapshot. Look at Coldsnap for that functionality

Usage: read_snapshot.exe [OPTIONS] --snapshot <SNAPSHOT> --offset <OFFSET> --length <LENGTH>

Options:
  -s, --snapshot <SNAPSHOT>  The name of the snapshot to read from
  -o, --offset <OFFSET>      The offset in the snapshot to start reading from
  -l, --length <LENGTH>      The length in bytes to read
      --logging <LOGGING>    The logging level to use [default: Info] [possible values: Off, Error, Warn, Info, Debug, Trace]
  -h, --help                 Print help information
  -V, --version              Print version information
```

Example:
```
aws-snap-io$ ./target/release/examples/read_snapshot --snapshot snap-0acad277e952dfa05 --offset 330010624 --length 1091 | xxd -r -p
Files originating with or related to Casablanca v2.6.0, a "Microsoft project for cloud-based client-server communication in native code using a modern asynchronous C++ API design. This project aims to help C++ developers connect to and interact with services." See https://github.com/Microsoft/cpprestsdk. This material is licensed under the terms of the Apache Software License v2.0 (see https://github.com/Microsoft/cpprestsdk/blob/master/license.txt), which state:

 ==++==

 Copyright (c) Microsoft Corporation. All rights reserved.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
```