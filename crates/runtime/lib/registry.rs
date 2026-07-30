//! Runtime backend registry, capability validation, and operation routing.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

use async_trait::async_trait;

use crate::{
    BackendCapabilities, BackendId, CommandRuntime, CreateSpec, DebugContext, DebugRuntime,
    ExecRequest, ExecStream, FileTransferRuntime, GuestEntry, GuestLayout, ImageInfo, ImageRuntime,
    Result, RuntimeError, RuntimeFeature, SandboxInfo, SandboxRuntime, SnapshotInfo,
    SnapshotRuntime, TerminalRuntime,
};

/// A runtime facade that selects a backend at creation time and routes later
/// operations from the backend namespace embedded in sandbox IDs.
pub struct RuntimeRegistry {
    default_backend: BackendId,
    snapshot_backend: Option<BackendId>,
    image_backend: Option<BackendId>,
    backends: BTreeMap<BackendId, Arc<dyn SandboxRuntime>>,
}

impl RuntimeRegistry {
    /// Create an empty registry without a snapshot/image storage backend.
    pub fn new(default_backend: BackendId) -> Self {
        Self {
            default_backend,
            snapshot_backend: None,
            image_backend: None,
            backends: BTreeMap::new(),
        }
    }

    /// Select one backend for both snapshot and image-cache operations.
    pub fn with_storage_backend(mut self, backend: BackendId) -> Self {
        self.snapshot_backend = Some(backend.clone());
        self.image_backend = Some(backend);
        self
    }

    /// Select the backend used for global snapshot operations.
    pub fn with_snapshot_backend(mut self, backend: BackendId) -> Self {
        self.snapshot_backend = Some(backend);
        self
    }

    /// Select the backend used for global image-cache operations.
    pub fn with_image_backend(mut self, backend: BackendId) -> Self {
        self.image_backend = Some(backend);
        self
    }

    /// Register one backend after validating its capability declaration.
    pub fn register(&mut self, runtime: Arc<dyn SandboxRuntime>) -> Result<()> {
        validate_runtime_contract(runtime.as_ref())?;
        let backend = runtime.backend_id();
        if self.backends.contains_key(&backend) {
            return Err(RuntimeError::Configuration(format!(
                "backend {backend:?} was registered more than once"
            )));
        }
        self.backends.insert(backend, runtime);
        Ok(())
    }

    /// Validate configured backend roles after registration is complete.
    pub fn validate(&self) -> Result<()> {
        self.backend(&self.default_backend)?;
        if let Some(snapshot_backend) = &self.snapshot_backend {
            let storage = self.backend(snapshot_backend)?;
            if storage.snapshot_runtime().is_none() {
                return Err(RuntimeError::Configuration(format!(
                    "snapshot backend {snapshot_backend} does not provide snapshot capability"
                )));
            }
        }
        if let Some(image_backend) = &self.image_backend {
            let storage = self.backend(image_backend)?;
            if storage.image_runtime().is_none() {
                return Err(RuntimeError::Configuration(format!(
                    "image backend {image_backend} does not provide image-cache capability"
                )));
            }
        }
        Ok(())
    }

    /// Return every registered backend capability declaration.
    pub fn all_capabilities(&self) -> Vec<BackendCapabilities> {
        self.backends
            .values()
            .map(|backend| backend.capabilities())
            .collect()
    }

    /// Run readiness checks for one explicitly selected backend.
    pub async fn doctor_backend(&self, backend: &BackendId) -> Result<Vec<(String, bool, String)>> {
        self.backend(backend)?.doctor().await
    }

    /// Return the guest filesystem layout declared by one backend.
    pub fn guest_layout_for(&self, backend: &BackendId) -> Result<GuestLayout> {
        Ok(self.backend(backend)?.guest_layout())
    }

    fn backend(&self, backend: &BackendId) -> Result<Arc<dyn SandboxRuntime>> {
        self.backends.get(backend).cloned().ok_or_else(|| {
            RuntimeError::Configuration(format!("backend {backend:?} is not registered"))
        })
    }

    fn backend_from_namespaced_id(&self, sandbox: &str) -> Option<Arc<dyn SandboxRuntime>> {
        let suffix = sandbox.strip_prefix("sbx_")?;
        self.backends.iter().find_map(|(name, backend)| {
            suffix
                .strip_prefix(name.as_str())
                .and_then(|suffix| suffix.strip_prefix('_'))
                .map(|_| Arc::clone(backend))
        })
    }

    async fn backend_for_sandbox(&self, sandbox: &str) -> Result<Arc<dyn SandboxRuntime>> {
        if let Some(backend) = self.backend_from_namespaced_id(sandbox) {
            return Ok(backend);
        }

        // Legacy IDs did not carry a backend namespace. Probe all registered
        // runtimes so sessions survive an upgrade or a changed host default.
        for backend in self.backends.values() {
            if backend.inspect(sandbox).await.is_ok() {
                return Ok(Arc::clone(backend));
            }
        }
        Err(RuntimeError::NotFound(sandbox.into()))
    }

    fn snapshot_storage(&self) -> Result<Arc<dyn SandboxRuntime>> {
        let backend = self.snapshot_backend.as_ref().ok_or_else(|| {
            RuntimeError::Unsupported("no snapshot storage backend is configured".into())
        })?;
        self.backend(backend)
    }

    fn image_storage(&self) -> Result<Arc<dyn SandboxRuntime>> {
        let backend = self.image_backend.as_ref().ok_or_else(|| {
            RuntimeError::Unsupported("no image-cache backend is configured".into())
        })?;
        self.backend(backend)
    }
}

#[async_trait]
impl SandboxRuntime for RuntimeRegistry {
    fn backend_id(&self) -> BackendId {
        BackendId::new("multi").expect("static backend identifier is valid")
    }

    fn capabilities(&self) -> BackendCapabilities {
        let mut boot_sources = BTreeSet::new();
        let mut features = BTreeSet::new();
        let mut architectures = BTreeSet::new();
        let mut accelerators = BTreeSet::new();
        for capability in self.all_capabilities() {
            boot_sources.extend(capability.boot_sources);
            features.extend(capability.features);
            architectures.extend(capability.architectures);
            accelerators.extend(capability.accelerators);
        }
        BackendCapabilities {
            backend: self.backend_id(),
            boot_sources: boot_sources.into_iter().collect(),
            features: features.into_iter().collect(),
            architectures: architectures.into_iter().collect(),
            accelerators: accelerators.into_iter().collect(),
        }
    }

    fn guest_layout(&self) -> GuestLayout {
        self.backends
            .get(&self.default_backend)
            .map(|backend| backend.guest_layout())
            .unwrap_or_default()
    }

    fn guest_layout_for(&self, backend: &BackendId) -> Result<GuestLayout> {
        RuntimeRegistry::guest_layout_for(self, backend)
    }

    fn command_runtime(&self) -> Option<&dyn CommandRuntime> {
        self.backends
            .values()
            .any(|backend| backend.command_runtime().is_some())
            .then_some(self)
    }

    fn terminal_runtime(&self) -> Option<&dyn TerminalRuntime> {
        self.backends
            .values()
            .any(|backend| backend.terminal_runtime().is_some())
            .then_some(self)
    }

    fn file_transfer_runtime(&self) -> Option<&dyn FileTransferRuntime> {
        self.backends
            .values()
            .any(|backend| backend.file_transfer_runtime().is_some())
            .then_some(self)
    }

    fn snapshot_runtime(&self) -> Option<&dyn SnapshotRuntime> {
        self.snapshot_backend
            .as_ref()
            .and_then(|backend| self.backends.get(backend))
            .and_then(|backend| backend.snapshot_runtime())
            .map(|_| self as &dyn SnapshotRuntime)
    }

    fn image_runtime(&self) -> Option<&dyn ImageRuntime> {
        self.image_backend
            .as_ref()
            .and_then(|backend| self.backends.get(backend))
            .and_then(|backend| backend.image_runtime())
            .map(|_| self as &dyn ImageRuntime)
    }

    fn debug_runtime(&self) -> Option<&dyn DebugRuntime> {
        self.backends
            .values()
            .any(|backend| backend.debug_runtime().is_some())
            .then_some(self)
    }

    async fn create(&self, spec: &CreateSpec) -> Result<SandboxInfo> {
        self.backend(&spec.backend)?.create(spec).await
    }

    async fn stop(&self, sandbox: &str) -> Result<()> {
        self.backend_for_sandbox(sandbox).await?.stop(sandbox).await
    }

    async fn kill(&self, sandbox: &str) -> Result<()> {
        self.backend_for_sandbox(sandbox).await?.kill(sandbox).await
    }

    async fn remove(&self, sandbox: &str) -> Result<()> {
        self.backend_for_sandbox(sandbox)
            .await?
            .remove(sandbox)
            .await
    }

    async fn list(&self) -> Result<Vec<SandboxInfo>> {
        let mut sandboxes = Vec::new();
        for backend in self.backends.values() {
            sandboxes.extend(backend.list().await?);
        }
        sandboxes.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(sandboxes)
    }

    async fn inspect(&self, sandbox: &str) -> Result<SandboxInfo> {
        self.backend_for_sandbox(sandbox)
            .await?
            .inspect(sandbox)
            .await
    }

    async fn doctor(&self) -> Result<Vec<(String, bool, String)>> {
        self.backend(&self.default_backend)?.doctor().await
    }
}

#[async_trait]
impl CommandRuntime for RuntimeRegistry {
    async fn exec_stream(&self, sandbox: &str, request: ExecRequest) -> Result<ExecStream> {
        let backend = self.backend_for_sandbox(sandbox).await?;
        let capability = backend
            .command_runtime()
            .ok_or_else(|| unsupported_capability(&backend.backend_id(), RuntimeFeature::Exec))?;
        capability.exec_stream(sandbox, request).await
    }
}

#[async_trait]
impl TerminalRuntime for RuntimeRegistry {
    async fn attach(&self, sandbox: &str, request: ExecRequest) -> Result<i32> {
        let backend = self.backend_for_sandbox(sandbox).await?;
        let capability = backend
            .terminal_runtime()
            .ok_or_else(|| unsupported_capability(&backend.backend_id(), RuntimeFeature::Attach))?;
        capability.attach(sandbox, request).await
    }
}

#[async_trait]
impl FileTransferRuntime for RuntimeRegistry {
    async fn mkdir(&self, sandbox: &str, guest_path: &str) -> Result<()> {
        let backend = self.backend_for_sandbox(sandbox).await?;
        transfer(&backend)?.mkdir(sandbox, guest_path).await
    }

    async fn put_file(
        &self,
        sandbox: &str,
        host_path: &Path,
        guest_path: &str,
        mode: u32,
    ) -> Result<()> {
        let backend = self.backend_for_sandbox(sandbox).await?;
        transfer(&backend)?
            .put_file(sandbox, host_path, guest_path, mode)
            .await
    }

    async fn symlink(&self, sandbox: &str, target: &str, guest_path: &str) -> Result<()> {
        let backend = self.backend_for_sandbox(sandbox).await?;
        transfer(&backend)?
            .symlink(sandbox, target, guest_path)
            .await
    }

    async fn set_mode(&self, sandbox: &str, guest_path: &str, mode: u32) -> Result<()> {
        let backend = self.backend_for_sandbox(sandbox).await?;
        transfer(&backend)?
            .set_mode(sandbox, guest_path, mode)
            .await
    }

    async fn list_dir(&self, sandbox: &str, guest_path: &str) -> Result<Vec<GuestEntry>> {
        let backend = self.backend_for_sandbox(sandbox).await?;
        transfer(&backend)?.list_dir(sandbox, guest_path).await
    }

    async fn get_file(&self, sandbox: &str, guest_path: &str, host_path: &Path) -> Result<()> {
        let backend = self.backend_for_sandbox(sandbox).await?;
        transfer(&backend)?
            .get_file(sandbox, guest_path, host_path)
            .await
    }
}

#[async_trait]
impl SnapshotRuntime for RuntimeRegistry {
    async fn create_snapshot(
        &self,
        name: &str,
        sandbox: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<SnapshotInfo> {
        let backend = self.backend_for_sandbox(sandbox).await?;
        let capability = backend.snapshot_runtime().ok_or_else(|| {
            unsupported_capability(&backend.backend_id(), RuntimeFeature::Snapshots)
        })?;
        capability.create_snapshot(name, sandbox, labels).await
    }

    async fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        let backend = self.snapshot_storage()?;
        storage_snapshots(&backend)?.list_snapshots().await
    }

    async fn inspect_snapshot(&self, name: &str) -> Result<SnapshotInfo> {
        let backend = self.snapshot_storage()?;
        storage_snapshots(&backend)?.inspect_snapshot(name).await
    }

    async fn remove_snapshot(&self, name: &str) -> Result<()> {
        let backend = self.snapshot_storage()?;
        storage_snapshots(&backend)?.remove_snapshot(name).await
    }
}

#[async_trait]
impl ImageRuntime for RuntimeRegistry {
    async fn list_images(&self) -> Result<Vec<ImageInfo>> {
        let backend = self.image_storage()?;
        storage_images(&backend)?.list_images().await
    }

    async fn remove_image(&self, reference: &str) -> Result<()> {
        let backend = self.image_storage()?;
        storage_images(&backend)?.remove_image(reference).await
    }
}

#[async_trait]
impl DebugRuntime for RuntimeRegistry {
    async fn debug_context(&self, sandbox: &str) -> Result<DebugContext> {
        let backend = self.backend_for_sandbox(sandbox).await?;
        let capability = backend.debug_runtime().ok_or_else(|| {
            unsupported_capability(&backend.backend_id(), RuntimeFeature::GdbStub)
        })?;
        capability.debug_context(sandbox).await
    }
}

fn transfer(runtime: &Arc<dyn SandboxRuntime>) -> Result<&dyn FileTransferRuntime> {
    runtime
        .file_transfer_runtime()
        .ok_or_else(|| unsupported_capability(&runtime.backend_id(), RuntimeFeature::FileTransfer))
}

fn storage_snapshots(runtime: &Arc<dyn SandboxRuntime>) -> Result<&dyn SnapshotRuntime> {
    runtime
        .snapshot_runtime()
        .ok_or_else(|| unsupported_capability(&runtime.backend_id(), RuntimeFeature::Snapshots))
}

fn storage_images(runtime: &Arc<dyn SandboxRuntime>) -> Result<&dyn ImageRuntime> {
    runtime
        .image_runtime()
        .ok_or_else(|| unsupported_capability(&runtime.backend_id(), RuntimeFeature::ImageCache))
}

fn unsupported_capability(backend: &BackendId, feature: RuntimeFeature) -> RuntimeError {
    RuntimeError::Unsupported(format!("backend {backend} does not support {feature:?}"))
}

fn validate_runtime_contract(runtime: &dyn SandboxRuntime) -> Result<()> {
    let backend = runtime.backend_id();
    let capabilities = runtime.capabilities();
    if capabilities.backend != backend {
        return Err(RuntimeError::Configuration(format!(
            "backend {backend} returned a capability descriptor for {}",
            capabilities.backend
        )));
    }

    let features: BTreeSet<_> = capabilities.features.iter().copied().collect();
    if features.len() != capabilities.features.len() {
        return Err(RuntimeError::Configuration(format!(
            "backend {backend} declares duplicate runtime features"
        )));
    }

    for (feature, implemented) in [
        (RuntimeFeature::Exec, runtime.command_runtime().is_some()),
        (RuntimeFeature::Attach, runtime.terminal_runtime().is_some()),
        (
            RuntimeFeature::FileTransfer,
            runtime.file_transfer_runtime().is_some(),
        ),
        (
            RuntimeFeature::Snapshots,
            runtime.snapshot_runtime().is_some(),
        ),
        (
            RuntimeFeature::ImageCache,
            runtime.image_runtime().is_some(),
        ),
        (RuntimeFeature::GdbStub, runtime.debug_runtime().is_some()),
    ] {
        if features.contains(&feature) != implemented {
            return Err(RuntimeError::Configuration(format!(
                "backend {backend} capability mismatch for {feature:?}: descriptor={}, implementation={implemented}",
                features.contains(&feature)
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MinimalRuntime {
        features: Vec<RuntimeFeature>,
    }

    #[async_trait]
    impl SandboxRuntime for MinimalRuntime {
        fn backend_id(&self) -> BackendId {
            BackendId::new("minimal").unwrap()
        }

        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                backend: self.backend_id(),
                boot_sources: vec![],
                features: self.features.clone(),
                architectures: vec![],
                accelerators: vec![],
            }
        }

        fn snapshot_runtime(&self) -> Option<&dyn SnapshotRuntime> {
            self.features
                .contains(&RuntimeFeature::Snapshots)
                .then_some(self)
        }

        async fn create(&self, _spec: &CreateSpec) -> Result<SandboxInfo> {
            Err(RuntimeError::Unsupported("create".into()))
        }

        async fn stop(&self, _sandbox: &str) -> Result<()> {
            Ok(())
        }

        async fn kill(&self, _sandbox: &str) -> Result<()> {
            Ok(())
        }

        async fn remove(&self, _sandbox: &str) -> Result<()> {
            Ok(())
        }

        async fn list(&self) -> Result<Vec<SandboxInfo>> {
            Ok(vec![])
        }

        async fn inspect(&self, sandbox: &str) -> Result<SandboxInfo> {
            Err(RuntimeError::NotFound(sandbox.into()))
        }

        async fn doctor(&self) -> Result<Vec<(String, bool, String)>> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl SnapshotRuntime for MinimalRuntime {
        async fn create_snapshot(
            &self,
            name: &str,
            _sandbox: &str,
            labels: &BTreeMap<String, String>,
        ) -> Result<SnapshotInfo> {
            Ok(SnapshotInfo {
                name: name.into(),
                digest: format!("sha256:{name}"),
                image: "minimal:latest".into(),
                image_manifest_digest: "sha256:base".into(),
                size_bytes: 0,
                created_at: None,
                labels: labels.clone(),
            })
        }

        async fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
            Ok(vec![])
        }

        async fn inspect_snapshot(&self, name: &str) -> Result<SnapshotInfo> {
            Err(RuntimeError::NotFound(name.into()))
        }

        async fn remove_snapshot(&self, _name: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lifecycle_only_backend_registers_without_optional_method_stubs() {
        let backend = BackendId::new("minimal").unwrap();
        let mut registry = RuntimeRegistry::new(backend);
        registry
            .register(Arc::new(MinimalRuntime { features: vec![] }))
            .unwrap();
        registry.validate().unwrap();
    }

    #[test]
    fn feature_declaration_must_match_implemented_capability() {
        let backend = BackendId::new("minimal").unwrap();
        let mut registry = RuntimeRegistry::new(backend);
        let error = registry
            .register(Arc::new(MinimalRuntime {
                features: vec![RuntimeFeature::Exec],
            }))
            .unwrap_err();
        assert!(error.to_string().contains("capability mismatch for Exec"));
    }

    #[test]
    fn snapshot_backend_does_not_need_image_capability() {
        let backend = BackendId::new("minimal").unwrap();
        let mut registry =
            RuntimeRegistry::new(backend.clone()).with_snapshot_backend(backend.clone());
        registry
            .register(Arc::new(MinimalRuntime {
                features: vec![RuntimeFeature::Snapshots],
            }))
            .unwrap();
        registry.validate().unwrap();
        assert!(registry.snapshot_runtime().is_some());
        assert!(registry.image_runtime().is_none());
    }
}
