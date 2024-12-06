// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;

use crate::{writeln_special, JailerError};

// Holds a cache of discovered mount points and cgroup hierarchies
#[derive(Debug)]
struct CgroupHierarchies {
    hierarchies: HashMap<String, PathBuf>,
}

impl CgroupHierarchies {
    // Constructs a new cache of hierarchies and mount points
    // It will discover cgroup mount points and hierarchies configured
    // on the system and cache the info required to create cgroups later
    // within this hierarchies
    fn new(proc_mounts_path: &str) -> Result<Self, JailerError> {
        let mut h = CgroupHierarchies {
            hierarchies: HashMap::new(),
        };

        // search PROC_MOUNTS for cgroup mount points
        let f = File::open(proc_mounts_path)
            .map_err(|err| JailerError::FileOpen(PathBuf::from(proc_mounts_path), err))?;

        // Regex courtesy of Filippo.
        // This will match on each line from /proc/mounts for both v1 and v2 mount points.
        //
        // /proc/mounts cointains lines that look like this:
        // cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
        // cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
        //
        // This Regex will extract:
        //      * "/sys/fs/cgroup/unified" in the "dir" capture group.
        //      * "2" in the "ver" capture group as the cgroup version taken from "cgroup2"; for v1,
        //        the "ver" capture group will be empty (len = 0).
        //      * "[...],relatime,cpu,cpuacct" in the "options" capture group; this is used for
        //        cgroupv1 to determine what controllers are mounted at the location.
        let re = Regex::new(
            r"^([a-z2]*)[[:space:]](?P<dir>.*)[[:space:]]cgroup(?P<ver>2?)[[:space:]](?P<options>.*)[[:space:]]0[[:space:]]0$",
        ).map_err(JailerError::RegEx)?;

        for l in BufReader::new(f).lines() {
            let l = l.map_err(|err| JailerError::ReadLine(PathBuf::from(proc_mounts_path), err))?;
            if let Some(capture) = re.captures(&l) {
                if capture["ver"].len() == 1 {
                    // Found the cgroupv2 unified mountpoint; with cgroupsv2 there is only one
                    // hierarchy so we insert it in the hashmap to use it later when creating
                    // cgroups
                    h.hierarchies
                        .insert("unified".to_string(), PathBuf::from(&capture["dir"]));
                    break;
                }
            }
        }

        Ok(h)
    }

    // Returns the path to the root of the hierarchy
    pub fn get_v2_hierarchy_path(&self) -> Result<&PathBuf, JailerError> {
        match self.hierarchies.get("unified") {
            Some(entry) => Ok(entry),
            None => Err(JailerError::CgroupHierarchyMissing(
                "cgroupsv2 hierarchy missing".to_string(),
            )),
        }
    }
}

// Allows creation of cgroups on the system for both versions
#[derive(Debug)]
pub struct CgroupConfigurationBuilder {
    hierarchies: CgroupHierarchies,
    cgroup_conf: CgroupConfiguration,
}

impl CgroupConfigurationBuilder {
    // Creates the builder object
    // It will initialize the CgroupHierarchy cache.
    pub fn new(proc_mounts_path: &str) -> Result<Self, JailerError> {
        let hierachies = CgroupHierarchies::new(proc_mounts_path)?;
        Ok(CgroupConfigurationBuilder {
            hierarchies: hierachies,
            cgroup_conf: CgroupConfiguration::V2(HashMap::new()),
        })
    }

    // Adds a cgroup property to the configuration
    pub fn add_cgroup_property(
        &mut self,
        file: String,
        value: String,
        id: &str,
        parent_cg: &Path,
    ) -> Result<(), JailerError> {
        match self.cgroup_conf {
            CgroupConfiguration::V2(ref mut cgroup_conf_v2) => {
                let path = self.hierarchies.get_v2_hierarchy_path()?;
                let cgroup = cgroup_conf_v2
                    .entry(String::from("unified"))
                    .or_insert(CgroupV2::new(id, parent_cg, path)?);
                cgroup.add_property(file, value)?;
                Ok(())
            }
        }
    }

    pub fn build(self) -> CgroupConfiguration {
        self.cgroup_conf
    }

    // Returns the path to the unified controller
    pub fn get_v2_hierarchy_path(&self) -> Result<&PathBuf, JailerError> {
        self.hierarchies.get_v2_hierarchy_path()
    }
}

#[derive(Debug)]
struct CgroupProperty {
    file: String,  // file representing the cgroup (e.g cpuset.mems).
    value: String, // value that will be written into the file.
}

#[derive(Debug)]
struct CgroupBase {
    properties: Vec<CgroupProperty>,
    location: PathBuf, // microVM cgroup location for the specific controller.
}

#[derive(Debug)]
pub struct CgroupV2 {
    base: CgroupBase,
    available_controllers: HashSet<String>,
}

pub trait Cgroup: Debug {
    // Adds a property (file-value) to the group
    fn add_property(&mut self, file: String, value: String) -> Result<(), JailerError>;

    // Write the all cgroup property values into the cgroup property files.
    fn write_values(&self) -> Result<(), JailerError>;

    // This function will assign the process associated with the pid to the respective cgroup.
    fn attach_pid(&self) -> Result<(), JailerError>;
}

#[derive(Debug)]
pub enum CgroupConfiguration {
    V2(HashMap<String, CgroupV2>),
}

impl CgroupConfiguration {
    pub fn setup(&self) -> Result<(), JailerError> {
        match self {
            Self::V2(ref conf) => setup_cgroup_conf(conf),
        }
    }
}

// Extract the controller name from the cgroup file. The cgroup file must follow
// this format: <cgroup_controller>.<cgroup_property>.
fn get_controller_from_filename(file: &str) -> Result<&str, JailerError> {
    let v: Vec<&str> = file.split('.').collect();

    // Check format <cgroup_controller>.<cgroup_property>
    if v.len() < 2 {
        return Err(JailerError::CgroupInvalidFile(file.to_string()));
    }

    Ok(v[0])
}

impl CgroupV2 {
    // Enables the specified controller along the cgroup nested path.
    // To be able to use a leaf controller within a nested cgroup hierarchy,
    // the controller needs to be enabled by writing to the cgroup.subtree_control
    // of it's parent. This rule applies recursively.
    fn write_all_subtree_control<P>(path: P, controller: &str) -> Result<(), JailerError>
    where
        P: AsRef<Path> + Debug,
    {
        let cg_subtree_ctrl = path.as_ref().join("cgroup.subtree_control");
        if !cg_subtree_ctrl.exists() {
            return Ok(());
        }
        let parent = match path.as_ref().parent() {
            Some(p) => p,
            None => {
                writeln_special(&cg_subtree_ctrl, format!("+{}", &controller))?;
                return Ok(());
            }
        };

        Self::write_all_subtree_control(parent, controller)?;
        writeln_special(&cg_subtree_ctrl, format!("+{}", &controller))
    }

    // Returns controllers that can be enabled from the cgroup path specified
    // by the mount_point parameter
    fn detect_available_controllers<P>(mount_point: P) -> HashSet<String>
    where
        P: AsRef<Path> + Debug,
    {
        let mut controllers = HashSet::new();
        let controller_list_file = mount_point.as_ref().join("cgroup.controllers");
        let f = match File::open(controller_list_file) {
            Ok(f) => f,
            Err(_) => return controllers,
        };

        for l in BufReader::new(f).lines().map_while(Result::ok) {
            for controller in l.split(' ') {
                controllers.insert(controller.to_string());
            }
        }
        controllers
    }

    // Create a new cgroupsv2 controller
    pub fn new(id: &str, parent_cg: &Path, unified_path: &Path) -> Result<Self, JailerError> {
        let mut path = unified_path.to_path_buf();

        path.push(parent_cg);
        path.push(id);
        Ok(CgroupV2 {
            base: CgroupBase {
                properties: Vec::new(),
                location: path,
            },
            available_controllers: Self::detect_available_controllers(unified_path),
        })
    }
}

impl Cgroup for CgroupV2 {
    fn add_property(&mut self, file: String, value: String) -> Result<(), JailerError> {
        let controller = get_controller_from_filename(&file)?;
        if self.available_controllers.contains(controller) {
            self.base.properties.push(CgroupProperty { file, value });
            Ok(())
        } else {
            Err(JailerError::CgroupControllerUnavailable(
                controller.to_string(),
            ))
        }
    }

    fn write_values(&self) -> Result<(), JailerError> {
        let mut enabled_controllers: HashSet<&str> = HashSet::new();

        // Create the cgroup directory for the controller.
        fs::create_dir_all(&self.base.location)
            .map_err(|err| JailerError::CreateDir(self.base.location.clone(), err))?;

        // Ok to unwrap since the path was just created.
        let parent = self.base.location.parent().unwrap();

        for property in self.base.properties.iter() {
            let controller = get_controller_from_filename(&property.file)?;
            // enable controllers only once
            if !enabled_controllers.contains(controller) {
                // Enable the controller in all parent directories
                CgroupV2::write_all_subtree_control(parent, controller)?;
                enabled_controllers.insert(controller);
            }
            writeln_special(&self.base.location.join(&property.file), &property.value)?;
        }

        Ok(())
    }

    fn attach_pid(&self) -> Result<(), JailerError> {
        let pid = process::id();
        let location = &self.base.location.join("cgroup.procs");

        writeln_special(location, pid)?;

        Ok(())
    }
}

pub fn setup_cgroup_conf(conf: &HashMap<String, impl Cgroup>) -> Result<(), JailerError> {
    // cgroups are iterated two times as some cgroups may require others (e.g cpuset requires
    // cpuset.mems and cpuset.cpus) to be set before attaching any pid.
    for cgroup in conf.values() {
        cgroup.write_values()?;
    }
    for cgroup in conf.values() {
        cgroup.attach_pid()?;
    }
    Ok(())
}

#[cfg(test)]
pub mod test_util {
    use std::fmt::Debug;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use vmm_sys_util::rand;

    #[derive(Debug)]
    pub struct MockCgroupFs {
        mounts_file: File,
        pub proc_mounts_path: String,
        pub sys_cgroups_path: String,
    }

    // Helper object that simulates the layout of the cgroup file system
    // This can be used for testing regardless of the availability of a particular
    // version of cgroups on the system
    impl MockCgroupFs {
        pub fn create_file_with_contents<P: AsRef<Path> + Debug>(
            filename: P,
            contents: &str,
        ) -> std::result::Result<(), std::io::Error> {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&filename)?;

            writeln!(file, "{}", contents)?;
            Ok(())
        }

        pub fn new() -> std::result::Result<MockCgroupFs, std::io::Error> {
            let mock_jailer_dir = format!(
                "/tmp/cloud-hypervisor/test/{}/jailer",
                rand::rand_alphanumerics(4).into_string().unwrap()
            );
            let mock_proc_mounts = format!("{}/{}", mock_jailer_dir, "proc/mounts",);
            let mock_sys_cgroups = format!("{}/{}", mock_jailer_dir, "sys_cgroup",);

            let mock_proc_dir = Path::new(&mock_proc_mounts).parent().unwrap();

            // create a mock /proc/mounts file in a temporary directory
            fs::create_dir_all(mock_proc_dir)?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(mock_proc_mounts.clone())?;
            Ok(MockCgroupFs {
                mounts_file: file,
                proc_mounts_path: mock_proc_mounts,
                sys_cgroups_path: mock_sys_cgroups,
            })
        }

        // Populate the mocked proc/mounts file with cgroupv2 entries
        // Also create a directory structure that simulates cgroupsv2 layout
        pub fn add_v2_mounts(&mut self) -> std::result::Result<(), std::io::Error> {
            writeln!(
                self.mounts_file,
                "cgroupv2 {}/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0",
                self.sys_cgroups_path,
            )?;
            let cg_unified_path = PathBuf::from(format!("{}/unified", self.sys_cgroups_path));
            fs::create_dir_all(&cg_unified_path)?;
            Self::create_file_with_contents(
                cg_unified_path.join("cgroup.controllers"),
                "cpuset cpu io memory pids",
            )?;
            Self::create_file_with_contents(cg_unified_path.join("cgroup.subtree_control"), "")?;
            Ok(())
        }

        // Populate the mocked proc/mounts file with cgroupv1 entries
        pub fn add_v1_mounts(&mut self) -> std::result::Result<(), std::io::Error> {
            let controllers = vec![
                "memory",
                "net_cls,net_prio",
                "pids",
                "cpuset",
                "cpu,cpuacct",
            ];

            for c in &controllers {
                writeln!(
                    self.mounts_file,
                    "cgroup {}/{} cgroup rw,nosuid,nodev,noexec,relatime,{} 0 0",
                    self.sys_cgroups_path, c, c,
                )?;
            }
            Ok(())
        }
    }

    // Cleanup created files when object goes out of scope
    impl Drop for MockCgroupFs {
        fn drop(&mut self) {
            let tmp_dir = Path::new(self.proc_mounts_path.as_str())
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap();
            let _ = fs::remove_dir_all(tmp_dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::io::BufReader;
    use std::path::PathBuf;

    use super::*;
    use crate::cgroup::test_util::MockCgroupFs;

    // Utility function to read the first line in a file
    fn read_first_line<P>(filename: P) -> std::result::Result<String, std::io::Error>
    where
        P: AsRef<Path> + Debug,
    {
        let file = File::open(filename)?;
        let mut reader = BufReader::new(file);
        let mut buf = String::new();
        reader.read_line(&mut buf)?;

        Ok(buf)
    }

    #[test]
    fn test_cgroup_conf_builder_v2() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v2_mounts().unwrap();
        let builder = CgroupConfigurationBuilder::new(mock_cgroups.proc_mounts_path.as_str());
        builder.unwrap();
    }

    #[test]
    fn test_cgroup_conf_builder_v2_with_v1_mounts() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();
        let builder = CgroupConfigurationBuilder::new(mock_cgroups.proc_mounts_path.as_str());
        builder.unwrap_err();
    }

    #[test]
    fn test_cgroup_conf_builder_v2_no_mounts() {
        let mock_cgroups = MockCgroupFs::new().unwrap();
        let builder = CgroupConfigurationBuilder::new(mock_cgroups.proc_mounts_path.as_str());
        builder.unwrap_err();
    }

    #[test]
    fn test_cgroup_conf_build() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v2_mounts().unwrap();

        let mut builder =
            CgroupConfigurationBuilder::new(mock_cgroups.proc_mounts_path.as_str()).unwrap();

        builder
            .add_cgroup_property(
                "cpuset.mems".to_string(),
                "1".to_string(),
                "101",
                Path::new("fc_test_cg"),
            )
            .unwrap();
        builder.build();
    }

    #[test]
    fn test_cgroup_conf_build_invalid() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();
        mock_cgroups.add_v2_mounts().unwrap();

        let mut builder =
            CgroupConfigurationBuilder::new(mock_cgroups.proc_mounts_path.as_str()).unwrap();
        builder
            .add_cgroup_property(
                "invalid.cg".to_string(),
                "1".to_string(),
                "101",
                Path::new("fc_test_cg"),
            )
            .unwrap_err();
    }

    #[test]
    fn test_cgroup_conf_v2_write_value() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v2_mounts().unwrap();
        let builder = CgroupConfigurationBuilder::new(mock_cgroups.proc_mounts_path.as_str());
        builder.unwrap();

        let mut builder =
            CgroupConfigurationBuilder::new(mock_cgroups.proc_mounts_path.as_str()).unwrap();
        builder
            .add_cgroup_property(
                "cpuset.mems".to_string(),
                "1".to_string(),
                "101",
                Path::new("fc_test_cgv2"),
            )
            .unwrap();

        let cg_root = PathBuf::from(format!("{}/unified", mock_cgroups.sys_cgroups_path));

        assert_eq!(builder.get_v2_hierarchy_path().unwrap(), &cg_root);

        let cg_conf = builder.build();

        // with real cgroups these files are created automatically
        // since the mock will not do it automatically, we create it here
        fs::create_dir_all(cg_root.join("fc_test_cgv2/101")).unwrap();
        MockCgroupFs::create_file_with_contents(
            cg_root.join("fc_test_cgv2/cgroup.subtree_control"),
            "",
        )
        .unwrap();
        MockCgroupFs::create_file_with_contents(
            cg_root.join("fc_test_cgv2/101/cgroup.subtree_control"),
            "",
        )
        .unwrap();

        cg_conf.setup().unwrap();

        // check that the value was written correctly
        assert!(cg_root.join("fc_test_cgv2/101/cpuset.mems").exists());
        assert_eq!(
            read_first_line(cg_root.join("fc_test_cgv2/101/cpuset.mems")).unwrap(),
            "1\n"
        );

        // check that the controller was enabled in all parent dirs
        assert!(read_first_line(cg_root.join("cgroup.subtree_control"))
            .unwrap()
            .contains("cpuset"));
        assert!(
            read_first_line(cg_root.join("fc_test_cgv2/cgroup.subtree_control"))
                .unwrap()
                .contains("cpuset")
        );
        assert!(
            !read_first_line(cg_root.join("fc_test_cgv2/101/cgroup.subtree_control"))
                .unwrap()
                .contains("cpuset")
        );
    }

    #[test]
    fn test_get_controller() {
        let mut file = "cpuset.cpu";

        // Check valid file.
        let mut result = get_controller_from_filename(file);
        assert!(
            matches!(result, Ok(ctrl) if ctrl == "cpuset"),
            "{:?}",
            result
        );

        // Check valid file with multiple '.'.
        file = "memory.swap.high";
        result = get_controller_from_filename(file);
        assert!(
            matches!(result, Ok(ctrl) if ctrl == "memory"),
            "{:?}",
            result
        );

        // Check invalid file
        file = "cpusetcpu";
        result = get_controller_from_filename(file);
        assert!(
            matches!(result, Err(JailerError::CgroupInvalidFile(_))),
            "{:?}",
            result
        );

        // Check empty file
        file = "";
        result = get_controller_from_filename(file);
        assert!(
            matches!(result, Err(JailerError::CgroupInvalidFile(_))),
            "{:?}",
            result
        );
    }
}
