package com.jmcardon.lc

import cats.effect.IO

import java.nio.charset.StandardCharsets

sealed abstract class Salsa20CSPRNG(key: Salsa20CSPRNG.Key,
                                    iv: Salsa20CSPRNG.Iv,
                                    ctrPos: Long,
                                    chnkSize: Int) {

  /** Check if we have overflowed our counter.
    *
    */
  def mustReseed(c1: Int, c2: Int): Boolean = {
    (Salsa20CSPRNG.littleEndianIntsToLong(c1, c2) + chnkSize.toLong) < 0L //overflow
  }

  private[this] def printBytes(bytes: Array[Byte]) =
    IO(print(new String(bytes, StandardCharsets.UTF_8)))

  /** Print an infinitely long stream of bytes to standard out, in chunks
    *
    * @return
    */
  def infiniteStream(): IO[Unit] = {
    def salsaChunk(ctr0: Int, ctr1: Int): IO[Unit] = {
      if (mustReseed(ctr0, ctr1)) {
        continueInfinite()
      } else {
        val (out, c1, c2) =
          Salsa20CSPRNG.salsa20Rand(chnkSize, key, iv, ctr0, ctr1)
        printBytes(out).flatMap(_ => salsaChunk(c1, c2))
      }
    }

    val (c0, c1) = Salsa20CSPRNG.longToLittleEndianInt(ctrPos)
    salsaChunk(c0, c1)
  }

  /** Prints the requested number of bytes from our
    * csprng
    */
  def randomStream(requested: Int): IO[Unit] = {
    require(requested > 0)
    def salsaChunk(left: Int, ctr0: Int, ctr1: Int): IO[Unit] = {
      if (mustReseed(ctr0, ctr1))
        continueFinite(left)
      else {
        val (out, c1, c2) =
          Salsa20CSPRNG.salsa20Rand(chnkSize, key, iv, ctr0, ctr1)
        if (left < chnkSize) {
          printBytes(out)
        } else {
          printBytes(out).flatMap(_ => salsaChunk(left - chnkSize, c1, c2))
        }
      }
    }

    val (c0, c1) = Salsa20CSPRNG.longToLittleEndianInt(ctrPos)
    salsaChunk(requested, c0, c1)
  }

  def reseed: IO[Salsa20CSPRNG] =
    Salsa20CSPRNG.paramsFromTcpdump.map {
      case (k, i) => new Salsa20CSPRNG(k, i, 0, chnkSize) {}
    }

  def continueFinite(remaining: Int): IO[Unit] =
    reseed.flatMap(_.randomStream(remaining))

  def continueInfinite(): IO[Unit] = {
    reseed.flatMap(_.infiniteStream())
  }

}

/** Taken from
  * https://cr.yp.to/snuffle/spec.pdf,
  * with minor adjustments for jvm things
  *
  */
object Salsa20CSPRNG {

  abstract class ByteArrayNewt {
    type Type
    def coerce(array: Array[Byte]): Type
    def flip(t: Type): Array[Byte]
  }

  protected val Salsa20Key: ByteArrayNewt = new ByteArrayNewt {
    type Type = Array[Byte]

    def coerce(array: Array[Byte]): Array[Byte] = array

    def flip(t: Array[Byte]): Array[Byte] = t
  }

  protected val Salsa20Iv: ByteArrayNewt = new ByteArrayNewt {
    type Type = Array[Byte]

    def coerce(array: Array[Byte]): Array[Byte] = array

    def flip(t: Array[Byte]): Array[Byte] = t
  }

  type Key = Salsa20Key.Type
  type Iv = Salsa20Iv.Type

  val KeyLength = 16
  val IvLength = 8
  val SalsaRounds = 20

  private[this] val Tau: Array[Int] = littleEndianToInt(
    "expand 16-byte k".getBytes(StandardCharsets.US_ASCII),
    0,
    4)

  def liftKey(array: Array[Byte]): Option[Key] = {
    liftNewt[Key](array, KeyLength, Salsa20Key.coerce)
  }

  def unsafeLiftKey(array: Array[Byte]): Key =
    if (array.length != 16) throw new IllegalArgumentException
    else Salsa20Key.coerce(array)

  def liftIv(array: Array[Byte]): Option[Iv] = {
    liftNewt[Iv](array, IvLength, Salsa20Iv.coerce)
  }

  def unsafeLiftIv(array: Array[Byte]): Iv = Salsa20Iv.coerce(array)

  private[this] def liftNewt[A](a: Array[Byte],
                                len: Int,
                                lift: Array[Byte] => A): Option[A] = {
    if (a.length == len)
      Some(lift(a))
    else
      None
  }

  private[Salsa20CSPRNG] def littleEndianIntsToLong(i1: Int, i2: Int): Long = {
    (i2.toLong << 32) | (i1 & 0xFFFFFFFFL)
  }

  private[Salsa20CSPRNG] def longToLittleEndianInt(l: Long): (Int, Int) = {
    (l.toInt, (l >> 32).toInt)
  }

  /** Generate a Salsa20 key and IV from tcpdump.
    * We ensure that we do not simply take the first n bytes we need, but
    * "randomly" (weak random, dependent on system nano time)
    * select at a point after at least 1kb of data to l
    */
  private def paramsFromTcpdump: IO[(Key, Iv)] = IO {
    val process = Runtime.getRuntime.exec("tcpdump -x")
    val keyBytes = new Array[Byte](KeyLength)
    val ivBytes = new Array[Byte](IvLength)
    val rand = new java.util.Random()
    val discardBuffer = new Array[Byte](10000)
    val pis = process.getInputStream
    //Discard a random amount of bytes
    pis.read(discardBuffer, 0, rand.nextInt(1024))
    pis.read(keyBytes, 0, keyBytes.length)
    pis.read(discardBuffer, 0, rand.nextInt(100))
    pis.read(ivBytes, 0, ivBytes.length)
    process.destroy()
    pis.close()
    (unsafeLiftKey(keyBytes), unsafeLiftIv(ivBytes))
  }

  def apply(chunkSize: Int = 100): IO[Salsa20CSPRNG] = {
    paramsFromTcpdump.map {
      case (key, iv) =>
        new Salsa20CSPRNG(key, iv, 0, chunkSize) {}
    }
  }

  /** Convert bytes, assumed to be in little endian order,
    * into an int32
    *
    * Note: Bytes are signed on the JVM, so (& 0xFF) returns the unsigned equivalent, as an integer
    * (bitwise ops are defined on integers)
    * @param bytes the bytes to convert.
    * @param offset the offset of the input array
    * @param count the number of ints to convert
    */
  private[this] def littleEndianToInt(bytes: Array[Byte],
                                      offset: Int,
                                      count: Int): Array[Int] = {
    require(bytes.length % 4 == 0 && bytes.length / 4 - count >= 0)
    def littleEndianBytesToInt(b: Array[Byte], off: Int): Int = {
      var n = b(off) & 0xFF
      n |= (b(off + 1) & 0xFF) << 8
      n |= (b(off + 2) & 0XFF) << 16
      n |= b(off + 3) << 24
      n
    }

    val out = new Array[Int](count)
    var off = offset
    var i = 0
    while (i < count) {
      out(i) = littleEndianBytesToInt(bytes, off)
      off += 4
      i += 1
    }
    out
  }

  /** Run our salsa20 function on our specified parameters, initializing the counter to
    * the specified value (held in two integers, as we are using a 64 bit counter).
    *
    * Note: this is not perfect. We must ensure we do not overflow our counters _before_ calling this method,
    * not after. This is done from the salsa20 class.
    *
    * `Key` and `Iv` serve as type-level evidence that they are constructed from the right length,
    * thus we do not perform length checks.
    *
    * @param requested the number of bytes to output from the keystream
    * @param key the 16 byte key
    * @param iv the initialization vector
    * @param ctr0 the last 32 bits of the counter
    * @param ctr1 the first 32 bits of the counter
    * @return
    */
  def salsa20Rand(requested: Int,
                  key: Key,
                  iv: Iv,
                  ctr0: Int,
                  ctr1: Int): (Array[Byte], Int, Int) = {
    def advanceCounter(st: Array[Int]): Unit = {
      st(8) += 1
      if (st(8) == 0) {
        st(9) += 1
      }
    }

    val state = new Array[Int](16)
    val buffer = new Array[Int](16)
    val keyStream = new Array[Byte](16 * 4)
    val out = new Array[Byte](requested)
    state(0) = Tau(0)
    state(5) = Tau(1)
    state(10) = Tau(2)
    state(15) = Tau(3)
    //State preload
    val keyIntBytes = littleEndianToInt(Salsa20Key.flip(key), 0, 4)
    System.arraycopy(keyIntBytes, 0, state, 1, 4)
    System.arraycopy(keyIntBytes, 0, state, 11, 4)
    System.arraycopy(littleEndianToInt(Salsa20Iv.flip(iv), 0, 2),
                     0,
                     state,
                     6,
                     2)
    //Return counter to previous set value
    state(8) = ctr0
    state(9) = ctr1

    genKeyStream(state, buffer, keyStream)

    var i = 0
    var stateIx: Int = 0
    while (i < out.length) {
      out(i) = keyStream(stateIx)
      //counter increments modulo 63
      stateIx = (stateIx + 1) & 63
      //Advance counter for every 64 bytes
      if (stateIx == 0) {
        advanceCounter(state)
        genKeyStream(state, buffer, keyStream)
      }
      i += 1
    }
    (out, state(8), state(9))
  }

  /** Get our keystream **/
  private[this] def genKeyStream(state: Array[Int],
                                 buf: Array[Int],
                                 output: Array[Byte]): Unit = {
    snuffle(state, buf)
    var i = 0
    var offset = 0
    while (i < buf.length) {
      intToLittleEndian(buf(i), output, offset)
      offset += 4
      i += 1
    }
  }

  /** Convert an int32 into the four byte representation,
    * in little endian format.
    *
    * Note: The JVM does this by truncating the first 24 bits, thus requiring
    * the shifts
    *
    * @param n the number to convert
    * @param out the out buffer
    * @param offset the buffer offset
    * @return the mutated buffer
    */
  private[this] def intToLittleEndian(n: Int,
                                      out: Array[Byte],
                                      offset: Int): Array[Byte] = {
    out(offset) = n.toByte
    out(offset + 1) = (n >>> 8).toByte
    out(offset + 2) = (n >>> 16).toByte
    out(offset + 3) = (n >>> 24).toByte
    out
  }

  /**
    * Salsa20 function.
    * Modified from the reference implementation in:
    * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c
    *
    * @param   in input data
    */
  private[this] def snuffle(in: Array[Int], x: Array[Int]): Unit = {
    var x00 = in(0)
    var x01 = in(1)
    var x02 = in(2)
    var x03 = in(3)
    var x04 = in(4)
    var x05 = in(5)
    var x06 = in(6)
    var x07 = in(7)
    var x08 = in(8)
    var x09 = in(9)
    var x10 = in(10)
    var x11 = in(11)
    var x12 = in(12)
    var x13 = in(13)
    var x14 = in(14)
    var x15 = in(15)

    var i = 0
    //Unrolls doubleRound in terms of leftRotation.
    while (i < SalsaRounds) {
      x04 ^= leftRot(x00 + x12, 7)
      x08 ^= leftRot(x04 + x00, 9)
      x12 ^= leftRot(x08 + x04, 13)
      x00 ^= leftRot(x12 + x08, 18)
      x09 ^= leftRot(x05 + x01, 7)
      x13 ^= leftRot(x09 + x05, 9)
      x01 ^= leftRot(x13 + x09, 13)
      x05 ^= leftRot(x01 + x13, 18)
      x14 ^= leftRot(x10 + x06, 7)
      x02 ^= leftRot(x14 + x10, 9)
      x06 ^= leftRot(x02 + x14, 13)
      x10 ^= leftRot(x06 + x02, 18)
      x03 ^= leftRot(x15 + x11, 7)
      x07 ^= leftRot(x03 + x15, 9)
      x11 ^= leftRot(x07 + x03, 13)
      x15 ^= leftRot(x11 + x07, 18)
      x01 ^= leftRot(x00 + x03, 7)
      x02 ^= leftRot(x01 + x00, 9)
      x03 ^= leftRot(x02 + x01, 13)
      x00 ^= leftRot(x03 + x02, 18)
      x06 ^= leftRot(x05 + x04, 7)
      x07 ^= leftRot(x06 + x05, 9)
      x04 ^= leftRot(x07 + x06, 13)
      x05 ^= leftRot(x04 + x07, 18)
      x11 ^= leftRot(x10 + x09, 7)
      x08 ^= leftRot(x11 + x10, 9)
      x09 ^= leftRot(x08 + x11, 13)
      x10 ^= leftRot(x09 + x08, 18)
      x12 ^= leftRot(x15 + x14, 7)
      x13 ^= leftRot(x12 + x15, 9)
      x14 ^= leftRot(x13 + x12, 13)
      x15 ^= leftRot(x14 + x13, 18)

      i += 2
    }
    x(0) = x00 + in(0)
    x(1) = x01 + in(1)
    x(2) = x02 + in(2)
    x(3) = x03 + in(3)
    x(4) = x04 + in(4)
    x(5) = x05 + in(5)
    x(6) = x06 + in(6)
    x(7) = x07 + in(7)
    x(8) = x08 + in(8)
    x(9) = x09 + in(9)
    x(10) = x10 + in(10)
    x(11) = x11 + in(11)
    x(12) = x12 + in(12)
    x(13) = x13 + in(13)
    x(14) = x14 + in(14)
    x(15) = x15 + in(15)
  }

  /** Left rotation as defined by djb **/
  def leftRot(x: Int, y: Int): Int = (x << y) | (x >>> -y)

}
