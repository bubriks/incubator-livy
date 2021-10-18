package org.apache.livy.server.interactive

import io.hops.security.{CertificateLocalizationCtx, CertificateLocalizationService}
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.security.UserGroupInformation
import org.apache.hadoop.security.authentication.client.AuthenticationException
import org.apache.hadoop.util.ShutdownHookManager
import org.apache.livy.{LivyConf, Logging}

import java.nio.charset.StandardCharsets
import java.io.FileNotFoundException
import java.nio.ByteBuffer
import java.util.Base64

object CertificateManager extends Logging{

  def initialize(request: CreateInteractiveRequest, proxyUser: Option[String]) {
    if (CertificateLocalizationCtx.getInstance.getCertificateLocalization == null) {
      startMetaStore
    }

    val username = proxyUser.get
    try{
      CertificateLocalizationCtx.getInstance.getCertificateLocalization.getX509MaterialLocation(username)
    } catch {
      case e: FileNotFoundException =>
        setCertificates(request, username)
    }
  }

  def startMetaStore(){
    // Create an instance of the CertificateLocalizationService to keep the track
    // of the certificates sent by the users
    val certLocService = new CertificateLocalizationService(CertificateLocalizationService.ServiceType.HM)
    certLocService.init(new Configuration())
    certLocService.start()
    CertificateLocalizationCtx.getInstance.setCertificateLocalization(certLocService)

    // Add shutdown hook to shutdown the CertificateLocalizationService
    ShutdownHookManager.get.addShutdownHook(new Runnable {
      override def run(): Unit = certLocService.stop
    }, 10)
  }

  def setCertificates(request: CreateInteractiveRequest, username: String) {
    var password: String = null
    var trustStore: ByteBuffer = null
    var keyStore: ByteBuffer = null
    request.cert foreach {
      case (key, value) =>
        if (key.endsWith(".key")) {
          password = value
        }
        else if (key.endsWith(".jks")) {
          val decoded = Base64.getDecoder().decode(value)
          val byteBuffer = ByteBuffer.wrap(decoded)

          if (key.endsWith("tstore.jks")) {
            trustStore = byteBuffer
          }
          else if (key.endsWith("kstore.jks")) {
            keyStore = byteBuffer
          }
        }
    }

    if(StandardCharsets.UTF_8.decode(keyStore).toString.contains(username)){
      CertificateLocalizationCtx.getInstance.getCertificateLocalization
        .materializeCertificates(username, username, keyStore, password, trustStore, password)
    }
    else{
      throw new AuthenticationException(s"$username does not correspond to information provided in the keystore file")
    }
  }
}
