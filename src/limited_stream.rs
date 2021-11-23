use futures_core::task::Poll;
use pin_project::pin_project;
use std::pin::Pin;

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("data length too long")]
    LengthTooLongError,
}

#[pin_project]
pub(crate) struct LimitedStream<St, E>
where
    St: futures_core::stream::Stream<Item = std::result::Result<bytes::Bytes, E>>,
    E: Into<Box<dyn std::error::Error>> + 'static,
{
    limit: usize,
    count: usize,
    #[pin]
    inner: St,
}

impl<St, E> LimitedStream<St, E>
where
    St: futures_core::stream::Stream<Item = std::result::Result<bytes::Bytes, E>>,
    E: Into<Box<dyn std::error::Error>> + 'static,
{
    pub(crate) fn new(stream: St, limit: usize) -> Self {
        Self {
            inner: stream,
            count: 0,
            limit,
        }
    }
}

impl<St, E> futures_core::stream::Stream for LimitedStream<St, E>
where
    St: futures_core::stream::Stream<Item = std::result::Result<bytes::Bytes, E>>,
    E: Into<Box<dyn std::error::Error>> + 'static,
{
    type Item = Result<bytes::Bytes, Box<dyn std::error::Error>>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut futures_core::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if this.count > this.limit {
            log::warn!(
                "stream is halted (limit={}, count={})",
                this.limit,
                this.count
            );
            return Poll::Ready(Some(Err(Error::LengthTooLongError.into())));
        }
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(v))) => {
                *this.count += v.len();
                Poll::Ready(Some(Ok(v)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
