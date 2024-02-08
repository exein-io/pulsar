use std::{
    fs::File,
    io::{self, prelude::*, BufReader},
};

use thiserror::Error;

static MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

#[derive(Error, Debug)]
pub enum MountinfoError {
    #[error("reading link failed {path}")]
    ReadFile {
        #[source]
        source: io::Error,
        path: String,
    },
    #[error("could not find cgroup2 filesystem mount")]
    Cgroup2NotFound,
}

/// Parses information about the mount point of the cgroup v2 hierarchy
/// filesystem from the given buffer reader. The buffer should contain
/// information about mounts provided by the kernel, which is usually available
/// in `/proc/<pid>/mountinfo`.
///
/// The format of the information is described in
/// [the kernel documentation](https://www.kernel.org/doc/Documentation/filesystems/proc.txt).
/// To sum it up, each line contains the following fields:
///
/// ```ignore
/// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
/// (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)
/// ```
///
/// Field 7 is optional, but might occur multiple times. The purpose of
/// separator `-` is to make it clear where the field 9 starts.
///
/// We are interested only in fields 5 (mount point) and 9 (filesystem type).
fn parse_cgroup2_mountpoint<R>(reader: BufReader<R>) -> Result<String, MountinfoError>
where
    R: Read,
{
    for line in reader.lines().map_while(Result::ok) {
        // Mountinfo is separated by `-` into two parts:
        //
        // * Information about the mount which consist of at least 6 fields,
        //   but can contain unknown number of optional fields. The `-`
        //   separator is used due to this uncertainity.
        // * Information about the filesystem.
        let mut halves = line.splitn(2, '-').map(String::from);
        let mount_info = match halves.next() {
            Some(mount_info) => mount_info,
            None => continue,
        };
        let filesystem_info = match halves.next() {
            Some(filesystem_info) => filesystem_info,
            None => continue,
        };

        let mount_parts: Vec<&str> = mount_info.split_whitespace().collect();
        let filesystem_parts: Vec<&str> = filesystem_info.split_whitespace().collect();

        // We are interested in:
        //
        // * The 1st field of filesystem information (filesystem type).
        // * The 4th field of mount information (mount point).
        let filesystem_type = match filesystem_parts.first() {
            Some(filesystem_type) => *filesystem_type,
            None => continue,
        };
        // If the filesystem type is `cgroup2`, return the mount point.
        // Otherwise, keep searching.
        if filesystem_type == "cgroup2" {
            let mountpoint = match mount_parts.get(4) {
                Some(mountpoint) => *mountpoint,
                None => continue,
            };
            return Ok(mountpoint.to_owned());
        }
    }

    Err(MountinfoError::Cgroup2NotFound)
}

/// Returns the mount point of the cgroup v2 hierarchy filesystem.
///
/// On the most of Linux distributions, it returns either `/sys/fs/cgroup` or
/// `/sys/fs/cgroup/unified`.
pub fn get_cgroup2_mountpoint() -> Result<String, MountinfoError> {
    let file = File::open(MOUNTINFO_PATH).map_err(|source| MountinfoError::ReadFile {
        source,
        path: MOUNTINFO_PATH.to_owned(),
    })?;

    let reader = BufReader::new(file);
    parse_cgroup2_mountpoint(reader)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_cgroup2() {
        let mountinfo = b"24 31 0:22 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
25 31 0:23 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
26 31 0:5 / /dev rw,nosuid,noexec - devtmpfs devtmpfs rw,size=10240k,nr_inodes=8117323,mode=755,inode64
27 26 0:24 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=000
28 26 0:25 / /dev/shm rw,nosuid,nodev,noexec - tmpfs tmpfs rw,inode64
29 31 0:26 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw,mode=755,inode64
31 1 0:27 / / rw,relatime - btrfs /dev/mapper/luks-316de005-f823-43c4-b6be-058f915d8d02 rw,ssd,space_cache=v2,subvolid=5,subvol=/
30 25 0:6 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime - securityfs securityfs rw
32 25 0:7 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime - debugfs debugfs rw
33 25 0:29 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime - pstore pstore rw
34 25 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - tmpfs cgroup_root rw,size=10240k,mode=755,inode64
35 34 0:31 / /sys/fs/cgroup/openrc rw,nosuid,nodev,noexec,relatime - cgroup openrc rw,release_agent=/lib/rc/sh/cgroup-release-agent.sh,name=openrc
36 34 0:32 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime - cgroup2 none rw,nsdelegate
37 34 0:33 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime - cgroup cpuset rw,cpuset
38 34 0:34 / /sys/fs/cgroup/cpu rw,nosuid,nodev,noexec,relatime - cgroup cpu rw,cpu
39 34 0:35 / /sys/fs/cgroup/cpuacct rw,nosuid,nodev,noexec,relatime - cgroup cpuacct rw,cpuacct
40 34 0:36 / /sys/fs/cgroup/blkio rw,nosuid,nodev,noexec,relatime - cgroup blkio rw,blkio
41 34 0:37 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime - cgroup memory rw,memory
42 34 0:38 / /sys/fs/cgroup/devices rw,nosuid,nodev,noexec,relatime - cgroup devices rw,devices
43 34 0:39 / /sys/fs/cgroup/freezer rw,nosuid,nodev,noexec,relatime - cgroup freezer rw,freezer
44 34 0:40 / /sys/fs/cgroup/net_cls rw,nosuid,nodev,noexec,relatime - cgroup net_cls rw,net_cls
45 34 0:41 / /sys/fs/cgroup/perf_event rw,nosuid,nodev,noexec,relatime - cgroup perf_event rw,perf_event
46 34 0:42 / /sys/fs/cgroup/net_prio rw,nosuid,nodev,noexec,relatime - cgroup net_prio rw,net_prio
47 34 0:43 / /sys/fs/cgroup/hugetlb rw,nosuid,nodev,noexec,relatime - cgroup hugetlb rw,hugetlb
48 34 0:44 / /sys/fs/cgroup/pids rw,nosuid,nodev,noexec,relatime - cgroup pids rw,pids
49 34 0:45 / /sys/fs/cgroup/rdma rw,nosuid,nodev,noexec,relatime - cgroup rdma rw,rdma
50 34 0:46 / /sys/fs/cgroup/misc rw,nosuid,nodev,noexec,relatime - cgroup misc rw,misc
51 26 0:20 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
52 24 0:47 / /proc/sys/fs/binfmt_misc rw,nosuid,nodev,noexec,relatime - binfmt_misc binfmt_misc rw
53 31 259:4 / /boot rw,relatime - vfat /dev/nvme1n1p1 rw,fmask=0022,dmask=0022,codepage=437,iocharset=iso8859-1,shortname=mixed,utf8,errors=remount-ro
55 29 0:49 / /run/user/1000 rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=6498984k,nr_inodes=1624746,mode=700,uid=1000,gid=1000,inode64
54 55 0:48 / /run/user/1000/doc rw,nosuid,nodev,relatime - fuse.portal portal rw,user_id=1000,group_id=1000
62 25 0:69 / /sys/fs/bpf rw,relatime - bpf bpf rw
63 32 0:12 / /sys/kernel/debug/tracing rw,nosuid,nodev,noexec,relatime - tracefs tracefs rw";

        let reader = BufReader::new(&mountinfo[..]);
        let result = parse_cgroup2_mountpoint(reader).unwrap();
        assert_eq!(result, "/sys/fs/cgroup/unified");
    }
}
