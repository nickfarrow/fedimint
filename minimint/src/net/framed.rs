use bytes::{BufMut, BytesMut};
use futures::{Sink, Stream};
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite};

/// Special case for tokio [`TcpStream`](tokio::net::TcpStream) based [`BidiFramed`] instances
pub type TcpBidiFramed<T> = BidiFramed<T, OwnedWriteHalf, OwnedReadHalf>;

/// Sink (sending) half of [`BidiFramed`]
pub type FramedSink<S, T> = FramedWrite<S, BincodeCodec<T>>;
/// Stream (receiving) half of [`BidiFramed`]
pub type FramedStream<S, T> = FramedRead<S, BincodeCodec<T>>;

/// Framed transport codec for streams
///
/// Wraps a stream `S` and allows sending packetized data of type `T` over it. Data items are
/// encoded using [`bincode`] and the bytes are sent over the stream prepended with a length field.
/// `BidiFramed` implements `Sink<T>` and `Stream<Item=Result<T, _>>`.
#[derive(Debug)]
pub struct BidiFramed<T, WH, RH> {
    sink: FramedSink<WH, T>,
    stream: FramedStream<RH, T>,
}

/// Framed codec that uses [`bincode`] to encode structs with [`serde`] support
#[derive(Debug)]
pub struct BincodeCodec<T> {
    _pd: PhantomData<T>,
}

impl<T, WH, RH> BidiFramed<T, WH, RH>
where
    WH: AsyncWrite,
    RH: AsyncRead,
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    /// Builds a new `BidiFramed` codec around a stream `stream`.
    ///
    /// See [`new_from_tcp`] for a more efficient version in case the stream is a tokio TCP stream.
    pub fn new<S>(stream: S) -> BidiFramed<T, WriteHalf<S>, ReadHalf<S>>
    where
        S: AsyncRead + AsyncWrite,
    {
        let (read, write) = tokio::io::split(stream);
        BidiFramed {
            sink: FramedSink::new(write, BincodeCodec::new()),
            stream: FramedStream::new(read, BincodeCodec::new()),
        }
    }

    /// Splits the codec in its sending and receiving parts
    ///
    /// This can be useful in cases where potentially simultaneous read and write operations are
    /// required. Otherwise a we would need a mutex to guard access.
    pub fn borrow_parts(&mut self) -> (&mut FramedSink<WH, T>, &mut FramedStream<RH, T>) {
        (&mut self.sink, &mut self.stream)
    }
}

impl<T> TcpBidiFramed<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    /// Special constructor for tokio TCP connections.
    ///
    /// Tokio [`TcpStream`](tokio::net::TcpStream) implements an efficient method of splitting the
    /// stream into a read and a write half this constructor takes advantage of.
    pub fn new_from_tcp(stream: tokio::net::TcpStream) -> TcpBidiFramed<T> {
        let (read, write) = stream.into_split();
        BidiFramed {
            sink: FramedSink::new(write, BincodeCodec::new()),
            stream: FramedStream::new(read, BincodeCodec::new()),
        }
    }
}

impl<T, WH, RH> Sink<T> for BidiFramed<T, WH, RH>
where
    WH: tokio::io::AsyncWrite + Unpin,
    RH: Unpin,
    T: serde::Serialize,
{
    type Error = <FramedSink<WH, T> as Sink<T>>::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::poll_ready(Pin::new(&mut self.sink), cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        Sink::start_send(Pin::new(&mut self.sink), item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::poll_flush(Pin::new(&mut self.sink), cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::poll_close(Pin::new(&mut self.sink), cx)
    }
}

impl<T, WH, RH> Stream for BidiFramed<T, WH, RH>
where
    T: serde::de::DeserializeOwned,
    WH: Unpin,
    RH: tokio::io::AsyncRead + Unpin,
{
    type Item = <FramedStream<RH, T> as Stream>::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Stream::poll_next(Pin::new(&mut self.stream), cx)
    }
}

impl<T> BincodeCodec<T> {
    fn new() -> BincodeCodec<T> {
        BincodeCodec {
            _pd: Default::default(),
        }
    }
}

impl<T> tokio_util::codec::Encoder<T> for BincodeCodec<T>
where
    T: serde::Serialize,
{
    type Error = bincode::Error;

    fn encode(&mut self, item: T, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        bincode::serialize_into(dst.writer(), &item)
    }
}

impl<T> tokio_util::codec::Decoder for BincodeCodec<T>
where
    T: serde::de::DeserializeOwned,
{
    type Item = T;
    type Error = bincode::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        bincode::deserialize(src).map(Option::Some)
    }
}
