//! Runtime backend registry and sandbox-operation routing.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

use async_trait::async_trait;

use crate::{
    BackendCapabilities, BackendId, CreateSpec, ExecRequest, ExecStream, GuestEntry, ImageInfo,
    Result, RuntimeError, SandboxInfo, SandboxRuntime, SnapshotInfo,
};

/// A runtime facade that selects a backend at creation time and routes later
/// operations from the backend namespace embedded in sandbox IDs.
pub struct RuntimeRegistry {
    default_backend: BackendId,
    storage_backend: BackendId,
    backends: BTreeMap<BackendId, Arc<dyn SandboxRuntime>>,
}

impl RuntimeRegistry {
    /// Create an empty registry.
    pub fn new(default_backend: BackendId, storage_backend: BackendId) -> Self {
        Self {
            default_backend,
            storage_backend,
            backends: BTreeMap::new(),
        }
    }

    /// Register one backend, rejecting duplicate identifiers.
    pub fn register(&mut self, runtime: Arc<dyn SandboxRuntime>) -> Result<()> {
        let backend = runtime.backend_id();
        if self.backends.insert(backend.clone(), runtime).is_some() {
            return Err(RuntimeError::Configuration(format!(
                "backend {backend:?} was registered more than once"
            )));
        }
        Ok(())
    }

    /// Validate that the configured default and storage backends exist.
    pub fn validate(&self) -> Result<()> {
        for (role, backend) in [
            ("default", &self.default_backend),
            ("storage", &self.storage_backend),
        ] {
            if !self.backends.contains_key(backend) {
                return Err(RuntimeError::Configuration(format!(
                    "{role} backend {backend:?} is not registered"
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

    fn storage(&self) -> Result<Arc<dyn SandboxRuntime>> {
        self.backend(&self.storage_backend)
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

    async fn create(&self, spec: &CreateSpec) -> Result<SandboxInfo> {
        self.backend(&spec.backend)?.create(spec).await
    }

    async fn exec_stream(&self, sandbox: &str, request: ExecRequest) -> Result<ExecStream> {
        self.backend_for_sandbox(sandbox)
            .await?
            .exec_stream(sandbox, request)
            .await
    }

    async fn attach(&self, sandbox: &str, request: ExecRequest) -> Result<i32> {
        self.backend_for_sandbox(sandbox)
            .await?
            .attach(sandbox, request)
            .await
    }

    async fn mkdir(&self, sandbox: &str, guest_path: &str) -> Result<()> {
        self.backend_for_sandbox(sandbox)
            .await?
            .mkdir(sandbox, guest_path)
            .await
    }

    async fn put_file(
        &self,
        sandbox: &str,
        host_path: &Path,
        guest_path: &str,
        mode: u32,
    ) -> Result<()> {
        self.backend_for_sandbox(sandbox)
            .await?
            .put_file(sandbox, host_path, guest_path, mode)
            .await
    }

    async fn symlink(&self, sandbox: &str, target: &str, guest_path: &str) -> Result<()> {
        self.backend_for_sandbox(sandbox)
            .await?
            .symlink(sandbox, target, guest_path)
            .await
    }

    async fn set_mode(&self, sandbox: &str, guest_path: &str, mode: u32) -> Result<()> {
        self.backend_for_sandbox(sandbox)
            .await?
            .set_mode(sandbox, guest_path, mode)
            .await
    }

    async fn list_dir(&self, sandbox: &str, guest_path: &str) -> Result<Vec<GuestEntry>> {
        self.backend_for_sandbox(sandbox)
            .await?
            .list_dir(sandbox, guest_path)
            .await
    }

    async fn get_file(&self, sandbox: &str, guest_path: &str, host_path: &Path) -> Result<()> {
        self.backend_for_sandbox(sandbox)
            .await?
            .get_file(sandbox, guest_path, host_path)
            .await
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

    async fn create_snapshot(
        &self,
        name: &str,
        sandbox: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<SnapshotInfo> {
        self.backend_for_sandbox(sandbox)
            .await?
            .create_snapshot(name, sandbox, labels)
            .await
    }

    async fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        self.storage()?.list_snapshots().await
    }

    async fn inspect_snapshot(&self, name: &str) -> Result<SnapshotInfo> {
        self.storage()?.inspect_snapshot(name).await
    }

    async fn remove_snapshot(&self, name: &str) -> Result<()> {
        self.storage()?.remove_snapshot(name).await
    }

    async fn list_images(&self) -> Result<Vec<ImageInfo>> {
        self.storage()?.list_images().await
    }

    async fn remove_image(&self, reference: &str) -> Result<()> {
        self.storage()?.remove_image(reference).await
    }
}
