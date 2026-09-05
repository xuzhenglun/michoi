//! `POST /resource` — camera snapshot endpoint (pad-gateway patch).
//!
//! HomeKit controllers request still images with a JSON body such as
//! `{"resource-type":"image","image-width":1280,"image-height":720}` and
//! expect a `200 image/jpeg` response. The image is produced by a
//! process-wide provider installed with [`set_snapshot_provider`].

use std::sync::{Arc, OnceLock};

use futures::future::{BoxFuture, FutureExt};
use hyper::{body, Body, Response, StatusCode, Uri};
use log::{debug, warn};
use serde::Deserialize;

use crate::{pointer, transport::http::handler::JsonHandlerExt, Result};

/// Returns a JPEG for the requested size, or `None` when no image is
/// available. Implementations may ignore the size hint.
pub type SnapshotProvider = Arc<dyn Fn(u32, u32) -> Option<Vec<u8>> + Send + Sync>;

static PROVIDER: OnceLock<SnapshotProvider> = OnceLock::new();

/// Installs the snapshot provider. Only the first call takes effect.
pub fn set_snapshot_provider(provider: SnapshotProvider) {
    let _ = PROVIDER.set(provider);
}

#[derive(Deserialize)]
struct ResourceRequest {
    #[serde(rename = "resource-type")]
    resource_type: String,
    #[serde(rename = "image-width", default)]
    image_width: u32,
    #[serde(rename = "image-height", default)]
    image_height: u32,
}

pub struct Resource;

impl Resource {
    pub fn new() -> Resource {
        Resource
    }
}

impl JsonHandlerExt for Resource {
    fn handle(
        &mut self,
        _: Uri,
        body: Body,
        _: pointer::ControllerId,
        _: pointer::EventSubscriptions,
        _: pointer::Config,
        _: pointer::Storage,
        _: pointer::AccessoryDatabase,
        _: pointer::EventEmitter,
    ) -> BoxFuture<Result<Response<Body>>> {
        async move {
            let bytes = body::to_bytes(body).await?;
            let request: ResourceRequest = match serde_json::from_slice(&bytes) {
                Ok(request) => request,
                Err(error) => {
                    warn!("invalid /resource request: {}", error);
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::empty())?);
                }
            };
            if request.resource_type != "image" {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())?);
            }
            let image = PROVIDER
                .get()
                .and_then(|provider| provider(request.image_width, request.image_height));
            match image {
                Some(jpeg) => {
                    debug!(
                        "snapshot {}x{} -> {} bytes",
                        request.image_width,
                        request.image_height,
                        jpeg.len()
                    );
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "image/jpeg")
                        .header("Content-Length", jpeg.len())
                        .body(Body::from(jpeg))?)
                }
                None => Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())?),
            }
        }
        .boxed()
    }
}
