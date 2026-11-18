rsbinder::include_aidl!("apex");
#[path = "../../../src/guest/apex_registry.rs"]
mod registry;
use android::apex::{
    ApexInfo::ApexInfo, ApexInfoList::ApexInfoList, ApexSessionInfo::ApexSessionInfo,
    ApexSessionParams::ApexSessionParams, CompressedApexInfoList::CompressedApexInfoList,
    IApexService::*,
};
use rsbinder::{BinderResult, ExceptionCode, Interface, Status};
use std::path::Path;

struct ApexService(Vec<ApexInfo>);
impl Interface for ApexService {}
fn denied<T>() -> BinderResult<T> {
    Err(Status::from(ExceptionCode::UnsupportedOperation))
}
impl IApexService for ApexService {
    fn getActivePackages(&self) -> BinderResult<Vec<ApexInfo>> {
        eprintln!(
            "guest_apex_call=getActivePackages count={} pid={} uid={}",
            self.0.len(),
            rsbinder::get_calling_pid(),
            rsbinder::get_calling_uid()
        );
        Ok(self.0.iter().filter(|p| p.isActive).cloned().collect())
    }
    fn getAllPackages(&self) -> BinderResult<Vec<ApexInfo>> {
        eprintln!(
            "guest_apex_call=getAllPackages count={} pid={} uid={}",
            self.0.len(),
            rsbinder::get_calling_pid(),
            rsbinder::get_calling_uid()
        );
        Ok(self.0.clone())
    }
    fn getSessions(&self) -> BinderResult<Vec<ApexSessionInfo>> {
        Ok(vec![])
    }
    fn getStagedSessionInfo(&self, id: i32) -> BinderResult<ApexSessionInfo> {
        Ok(ApexSessionInfo {
            sessionId: id,
            isUnknown: true,
            ..Default::default()
        })
    }
    fn getStagedApexInfos(&self, _: &ApexSessionParams) -> BinderResult<Vec<ApexInfo>> {
        Ok(vec![])
    }
    fn submitStagedSession(&self, _: &ApexSessionParams, _: &mut ApexInfoList) -> BinderResult<()> {
        denied()
    }
    fn markStagedSessionReady(&self, _: i32) -> BinderResult<()> {
        denied()
    }
    fn markStagedSessionSuccessful(&self, _: i32) -> BinderResult<()> {
        denied()
    }
    fn abortStagedSession(&self, _: i32) -> BinderResult<()> {
        denied()
    }
    fn revertActiveSessions(&self) -> BinderResult<()> {
        denied()
    }
    fn snapshotCeData(&self, _: i32, _: i32, _: &str) -> BinderResult<()> {
        denied()
    }
    fn restoreCeData(&self, _: i32, _: i32, _: &str) -> BinderResult<()> {
        denied()
    }
    fn destroyDeSnapshots(&self, _: i32) -> BinderResult<()> {
        denied()
    }
    fn destroyCeSnapshots(&self, _: i32, _: i32) -> BinderResult<()> {
        denied()
    }
    fn destroyCeSnapshotsNotSpecified(&self, _: i32, _: &[i32]) -> BinderResult<()> {
        denied()
    }
    fn unstagePackages(&self, _: &[String]) -> BinderResult<()> {
        denied()
    }
    fn stagePackages(&self, _: &[String]) -> BinderResult<()> {
        denied()
    }
    fn resumeRevertIfNeeded(&self) -> BinderResult<()> {
        denied()
    }
    fn recollectPreinstalledData(&self) -> BinderResult<()> {
        denied()
    }
    fn markBootCompleted(&self) -> BinderResult<()> {
        denied()
    }
    fn calculateSizeForCompressedApex(&self, _: &CompressedApexInfoList) -> BinderResult<i64> {
        denied()
    }
    fn reserveSpaceForCompressedApex(&self, _: &CompressedApexInfoList) -> BinderResult<()> {
        denied()
    }
    fn installAndActivatePackage(&self, _: &str, _: bool) -> BinderResult<ApexInfo> {
        denied()
    }
}

fn load() -> ssal_binder_service::Result<ApexService> {
    let packages: Vec<registry::Package> = serde_json::from_slice(&std::fs::read(registry::PATH)?)?;
    registry::validate(&packages)?;
    let mut infos = Vec::new();
    for p in packages {
        let manifest = Path::new(&p.mount_path).join("apex_manifest.pb");
        for path in [Path::new(&p.module_path), manifest.as_path()] {
            let metadata = path
                .metadata()
                .map_err(|e| format!("APEX {} at {}: {e}", p.module_name, path.display()))?;
            if !metadata.is_file() {
                return Err(format!("APEX {} at {} is not a file", p.module_name, path.display()).into());
            }
        }
        infos.push(ApexInfo {
            moduleName: p.module_name,
            modulePath: p.module_path,
            preinstalledModulePath: p.source_path,
            versionCode: p.version_code,
            // AIDL's non-null string uses the protobuf default when the optional field is absent.
            versionName: p.version_name.unwrap_or_default(),
            isFactory: true,
            isActive: p.is_active,
            partition: android::apex::ApexInfo::Partition::Partition(p.partition),
            ..Default::default()
        });
    }
    Ok(ApexService(infos))
}

fn run() -> ssal_binder_service::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 || !matches!(args[1].as_str(), "serve" | "check") {
        return Err("usage: ssal-apexservice serve|check GUEST_BINDER_RDEV GUEST_CONTEXT".into());
    }
    let service = load()?;
    ssal_binder_service::init(args[2].parse()?, &args[3])?;
    if args[1] == "check" {
        let remote: rsbinder::Strong<dyn IApexService> =
            rsbinder::hub::check_interface("apexservice")?;
        let all = remote.getAllPackages()?;
        if all != service.0 || remote.getActivePackages()? != service.getActivePackages()? {
            return Err("Guest APEX AIDL results differ from mount registry".into());
        }
        if remote
            .installAndActivatePackage("/no-install", false)
            .unwrap_err()
            .exception_code()
            != ExceptionCode::UnsupportedOperation
        {
            return Err("APEX mutation was not explicitly rejected".into());
        }
        println!("guest_apex_aidl=PASS packages={}", all.len());
        return Ok(());
    }
    ssal_binder_service::register("apexservice", BnApexService::new_binder(service))?;
    ssal_binder_service::join()
}

fn main() {
    if let Err(e) = run() {
        eprintln!("guest_apex_error={e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aidl_transaction_numbers_match_gsi() {
        assert_eq!(
            [
                transactions::submitStagedSession,
                transactions::markStagedSessionReady,
                transactions::markStagedSessionSuccessful,
                transactions::getSessions,
                transactions::getStagedSessionInfo,
                transactions::getStagedApexInfos,
                transactions::getActivePackages,
                transactions::getAllPackages,
                transactions::abortStagedSession,
                transactions::revertActiveSessions,
                transactions::snapshotCeData,
                transactions::restoreCeData,
                transactions::destroyDeSnapshots,
                transactions::destroyCeSnapshots,
                transactions::destroyCeSnapshotsNotSpecified,
                transactions::unstagePackages,
                transactions::stagePackages,
                transactions::resumeRevertIfNeeded,
                transactions::recollectPreinstalledData,
                transactions::markBootCompleted,
                transactions::calculateSizeForCompressedApex,
                transactions::reserveSpaceForCompressedApex,
                transactions::installAndActivatePackage,
            ],
            std::array::from_fn::<_, 23, _>(|i| i as u32 + 1)
        );
    }

    #[test]
    fn mutations_are_explicitly_unsupported() {
        let s = ApexService(vec![]);
        let params = ApexSessionParams::default();
        let compressed = CompressedApexInfoList::default();
        for result in [
            s.submitStagedSession(&params, &mut ApexInfoList::default()),
            s.markStagedSessionReady(1),
            s.markStagedSessionSuccessful(1),
            s.abortStagedSession(1),
            s.revertActiveSessions(),
            s.snapshotCeData(0, 1, "art"),
            s.restoreCeData(0, 1, "art"),
            s.destroyDeSnapshots(1),
            s.destroyCeSnapshots(0, 1),
            s.destroyCeSnapshotsNotSpecified(0, &[]),
            s.unstagePackages(&[]),
            s.stagePackages(&[]),
            s.resumeRevertIfNeeded(),
            s.recollectPreinstalledData(),
            s.markBootCompleted(),
            s.calculateSizeForCompressedApex(&compressed).map(|_| ()),
            s.reserveSpaceForCompressedApex(&compressed),
            s.installAndActivatePackage("/ignored", true).map(|_| ()),
        ] {
            assert_eq!(
                result.unwrap_err().exception_code(),
                ExceptionCode::UnsupportedOperation
            );
        }
    }

    #[test]
    fn session_parcel_matches_gsi() -> Result<(), Box<dyn std::error::Error>> {
        use rsbinder::Parcelable;
        let s = ApexService(vec![]).getStagedSessionInfo(42)?;
        let mut p = rsbinder::Parcel::new();
        s.write_to_parcel(&mut p)?;
        let size = p.data_size();
        p.set_data_position(0);
        assert_eq!(p.read::<i32>()?, size as i32);
        assert_eq!(p.read::<i32>()?, 42);
        for value in [1i32, 0, 0, 0, 0, 0, 0, 0, 0] {
            assert_eq!(p.read::<i32>()?, value);
        }
        assert_eq!(p.read::<String>()?, "");
        assert_eq!(p.read::<String>()?, "");
        assert_eq!(p.data_position(), size);
        Ok(())
    }
    #[test]
    fn parcel_matches_gsi_field_order_and_size() -> Result<(), Box<dyn std::error::Error>> {
        use rsbinder::Parcelable;
        let info = ApexInfo {
            moduleName: "com.android.art".into(),
            modulePath: "/apex/.packages/0.apex".into(),
            preinstalledModulePath: "/system/apex/art.capex".into(),
            versionCode: 300,
            versionName: "v".into(),
            isFactory: true,
            isActive: true,
            ..Default::default()
        };
        let mut p = rsbinder::Parcel::new();
        info.write_to_parcel(&mut p)?;
        let size = p.data_size();
        p.set_data_position(0);
        assert_eq!(p.read::<i32>()?, size as i32);
        assert_eq!(p.read::<String>()?, info.moduleName);
        assert_eq!(p.read::<String>()?, info.modulePath);
        assert_eq!(p.read::<String>()?, info.preinstalledModulePath);
        assert_eq!(p.read::<i64>()?, 300);
        assert_eq!(p.read::<String>()?, "v");
        for value in [1i32, 1, 0, 0, 0] {
            assert_eq!(p.read::<i32>()?, value);
        }
        assert_eq!(p.data_position(), size);
        p.set_data_position(0);
        let mut roundtrip = ApexInfo::default();
        roundtrip.read_from_parcel(&mut p)?;
        assert_eq!(roundtrip, info);
        let service = ApexService(vec![info]);
        assert_eq!(service.getAllPackages()?, service.getActivePackages()?);
        assert!(service.getSessions()?.is_empty());
        assert!(service.getStagedSessionInfo(42)?.isUnknown);
        assert_eq!(
            service.markBootCompleted().unwrap_err().exception_code(),
            ExceptionCode::UnsupportedOperation
        );
        Ok(())
    }
}
