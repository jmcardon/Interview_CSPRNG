lazy val root = (project in file("."))
  .settings(
    organization := "com.jmcardon",
    name := "symbiont-interv",
    version := "0.0.1",
    scalaVersion := "2.12.6",
    libraryDependencies += "org.typelevel" %% "cats-effect" % "0.10.1",
    mainClass in assembly := Some("com.jmcardon.lc.RandomApp"),
    assemblyJarName := "random.jar"
  )
