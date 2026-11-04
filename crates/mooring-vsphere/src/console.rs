//! Console paths (ADR-0015 §4, owner decision 7):
//!
//! 1. **Open in vSphere Client** (default): a deep link
//!    `https://<vcenter>/ui/app/vm;nav=v/urn:vmomi:VirtualMachine:<vm-moref>:<vcenter-instance-uuid>/summary`.
//!    The UUID is the **vCenter Server instance UUID** (`ServiceContent.about.instanceUuid`),
//!    not the VM's instance UUID (William Lam, "Generating a vSphere UI link to a specific
//!    virtual machine", 2023-04). `nav=v` opens the VMs-and-templates view. Without the UUID
//!    the link falls back to `https://<vcenter>/ui/`. No secret is ever in the URL.
//! 2. **VMRC** (opt-in): `POST /api/vcenter/vm/{vm}/console/tickets {"type":"VMRC"}` → a
//!    single-use `vmrc://clone:<ticket>@<vcenter>/?moid=<vm>` URL that K4 hands to the OS URL
//!    handler after its confirmation. The REST response carries no lifetime, so we treat the
//!    ticket as valid for [`VMRC_TICKET_TTL`] and refuse to hand it out later.

use std::time::Duration;

use bytes::Bytes;
use mooring_http::{decode_json, Method};
use time::OffsetDateTime;
use url::Url;
use zeroize::Zeroizing;

use crate::error::VsphereError;
use crate::ids::{is_uuid, MoId};
use crate::model::TicketResponse;
use crate::session::Session;

/// How long a VMRC ticket is handed out after it was issued.
pub const VMRC_TICKET_TTL: Duration = Duration::from_secs(60);
/// Longest ticket URL accepted.
pub const MAX_TICKET_URL: usize = 2048;

/// The "Open in vSphere Client" URL for `vm` on the vCenter at `base`.
pub fn vsphere_client_url(
    base: &Url,
    vm: &MoId,
    vcenter_instance_uuid: Option<&str>,
) -> Result<Url, VsphereError> {
    crate::session::check_base(base)?;
    let host = base.host_str().ok_or(VsphereError::Invalid("vCenter URL has no host"))?;
    let mut url =
        Url::parse("https://vcenter.invalid/").map_err(|_| VsphereError::Invalid("vCenter URL"))?;
    url.set_host(Some(host)).map_err(|_| VsphereError::Invalid("vCenter host"))?;
    url.set_port(base.port()).map_err(|()| VsphereError::Invalid("vCenter port"))?;
    match vcenter_instance_uuid {
        None => url.set_path("/ui/"),
        Some(u) if is_uuid(u) => {
            url.set_path(&format!("/ui/app/vm;nav=v/urn:vmomi:VirtualMachine:{vm}:{u}/summary"));
        }
        Some(_) => return Err(VsphereError::Invalid("vCenter instance UUID must be canonical")),
    }
    Ok(url)
}

/// A VMRC ticket URL. `Debug` never shows it; read it with [`VmrcUrl::expose_for_open`].
pub struct VmrcUrl {
    url: Zeroizing<String>,
    vm: MoId,
    issued_at: OffsetDateTime,
}

impl std::fmt::Debug for VmrcUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmrcUrl")
            .field("vm", &self.vm)
            .field("issued_at", &self.issued_at)
            .finish_non_exhaustive()
    }
}

impl VmrcUrl {
    /// The VM.
    pub fn vm(&self) -> &MoId {
        &self.vm
    }

    /// When the ticket stops being handed out.
    pub fn expires_at(&self) -> OffsetDateTime {
        self.issued_at + VMRC_TICKET_TTL
    }

    /// The URL for the OS `open` hand-off (fixed argv, never logged), or an error once the
    /// TTL has passed (request a new ticket then).
    pub fn expose_for_open(&self, now: OffsetDateTime) -> Result<&str, VsphereError> {
        if now >= self.expires_at() {
            return Err(VsphereError::Invalid("VMRC ticket expired"));
        }
        Ok(&self.url)
    }
}

/// Validate a ticket URL: `vmrc://…@<vcenter host>/?moid=<vm>`, ≤ 2 KiB visible ASCII, no
/// fragment, the host equal to the vCenter we asked, `moid` equal to the VM we asked for.
pub fn parse_vmrc_ticket(
    raw: &str,
    vcenter_host: &str,
    vm: &MoId,
) -> Result<Zeroizing<String>, VsphereError> {
    let bad = VsphereError::BadResponse("VMRC ticket");
    if raw.is_empty() || raw.len() > MAX_TICKET_URL || !raw.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(bad);
    }
    let url = Url::parse(raw).map_err(|_| VsphereError::BadResponse("VMRC ticket"))?;
    let host_ok = url.host_str().is_some_and(|h| h.eq_ignore_ascii_case(vcenter_host));
    let mut moids = url.query_pairs().filter(|(k, _)| k == "moid");
    let moid_ok = moids.next().is_some_and(|(_, v)| v == vm.as_str()) && moids.next().is_none();
    if url.scheme() != "vmrc" || url.fragment().is_some() || !host_ok || !moid_ok {
        return Err(bad);
    }
    Ok(Zeroizing::new(raw.to_owned()))
}

impl Session {
    /// "Open in vSphere Client" for `vm` (see the module docs for the UUID).
    pub fn vsphere_client_url(
        &self,
        vm: &MoId,
        vcenter_instance_uuid: Option<&str>,
    ) -> Result<Url, VsphereError> {
        vsphere_client_url(&self.base, vm, vcenter_instance_uuid)
    }

    /// Acquire a VMRC ticket (opt-in per connection; K4 checks the option and confirms
    /// before opening). Never logged; audit `vsphere.console { vm, kind: vmrc }` is K4's.
    pub async fn vmrc_ticket(&self, vm: &MoId) -> Result<VmrcUrl, VsphereError> {
        let path = format!("/api/vcenter/vm/{vm}/console/tickets");
        let body = Bytes::from_static(br#"{"type":"VMRC"}"#);
        let r = self.call(Method::POST, &path, Some(body)).await?;
        if r.body.len() > 2 * MAX_TICKET_URL {
            return Err(VsphereError::BadResponse("VMRC ticket"));
        }
        let t: TicketResponse = decode_json(&r.body)?;
        let raw = Zeroizing::new(t.ticket);
        let host = self.base.host_str().ok_or(VsphereError::Invalid("vCenter URL has no host"))?;
        let url = parse_vmrc_ticket(&raw, host, vm)?;
        Ok(VmrcUrl { url, vm: vm.clone(), issued_at: OffsetDateTime::now_utc() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "6f1b2c3d-0000-4abc-9def-0123456789ab";

    fn base() -> Url {
        Url::parse("https://vc.example.test:8443/").expect("url")
    }

    #[test]
    fn client_url_forms() {
        let vm = MoId::new("vm-42").expect("id");
        let u = vsphere_client_url(&base(), &vm, Some(UUID)).expect("url");
        assert_eq!(
            u.as_str(),
            "https://vc.example.test:8443/ui/app/vm;nav=v/urn:vmomi:VirtualMachine:vm-42:6f1b2c3d-0000-4abc-9def-0123456789ab/summary"
        );
        let plain = vsphere_client_url(&Url::parse("http://192.0.2.5/").expect("u"), &vm, None)
            .expect("url");
        assert_eq!(plain.as_str(), "https://192.0.2.5/ui/");
        assert!(vsphere_client_url(&base(), &vm, Some("x/../../evil")).is_err());
        assert!(vsphere_client_url(
            &Url::parse("https://vc.example.test/ui").expect("u"),
            &vm,
            None
        )
        .is_err());
        assert!(MoId::new("vm-1/../../admin").is_err(), "id injection refused at the type");
    }

    #[test]
    fn ticket_validation() {
        let vm = MoId::new("vm-42").expect("id");
        let ok = "vmrc://clone:cst-VCT-52a1-SECRET--tp-AB@vc.example.test/?moid=vm-42";
        assert_eq!(parse_vmrc_ticket(ok, "VC.example.test", &vm).expect("ok").as_str(), ok);
        for bad in [
            "https://vc.example.test/?moid=vm-42",
            "vmrc://clone:x@evil.example.test/?moid=vm-42",
            "vmrc://clone:x@vc.example.test/?moid=vm-43",
            "vmrc://clone:x@vc.example.test/?moid=vm-42&moid=vm-43",
            "vmrc://clone:x@vc.example.test/?moid=vm-42#f",
            "vmrc://clone:x@vc.example.test/ ?moid=vm-42",
            "",
        ] {
            assert!(parse_vmrc_ticket(bad, "vc.example.test", &vm).is_err(), "{bad}");
        }
        let long =
            format!("vmrc://clone:{}@vc.example.test/?moid=vm-42", "a".repeat(MAX_TICKET_URL));
        assert!(parse_vmrc_ticket(&long, "vc.example.test", &vm).is_err());
    }

    #[test]
    fn ticket_ttl_and_redaction() {
        let vm = MoId::new("vm-42").expect("id");
        let t0 = OffsetDateTime::UNIX_EPOCH;
        let v = VmrcUrl {
            url: Zeroizing::new("vmrc://clone:SECRET@h/?moid=vm-42".into()),
            vm,
            issued_at: t0,
        };
        assert!(!format!("{v:?}").contains("SECRET"));
        assert!(v.expose_for_open(t0 + Duration::from_secs(59)).is_ok());
        assert!(v.expose_for_open(t0 + VMRC_TICKET_TTL).is_err());
    }
}
