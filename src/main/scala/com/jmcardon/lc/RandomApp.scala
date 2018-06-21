package com.jmcardon.lc

import cats.effect.IO

object RandomApp {

  def main(args: Array[String]): Unit = {
    if (args.length == 0)
      Salsa20CSPRNG().flatMap(_.infiniteStream()).unsafeRunSync()
    else {
      IO(args(0).toInt.abs).attempt
        .flatMap {
          case Right(i) =>
            Salsa20CSPRNG().flatMap(_.randomStream(i))
          case Left(_) =>
            IO(
              println(
                "Program takes a single integer for random requested bytes"))
        }
        .unsafeRunSync()
    }
  }
}
