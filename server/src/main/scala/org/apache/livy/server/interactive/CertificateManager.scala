package org.apache.livy.server.interactive

import io.hops.security.{CertificateLocalizationCtx, CertificateLocalizationService}
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.security.UserGroupInformation
import org.apache.hadoop.util.ShutdownHookManager
import org.apache.livy.Logging

import java.nio.ByteBuffer
import java.util.Base64

object CertificateManager extends Logging{

  private var certLocService: CertificateLocalizationService = null;
  private var shutdownHookMgr: ShutdownHookManager = null

  def create(request: CreateInteractiveRequest) {
    if (CertificateLocalizationCtx.getInstance.getCertificateLocalization() == null) {
      startMetaStore

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

      setCrypto(keyStore, trustStore, password)
    }
  }

  def startMetaStore(){
    // Create an instance of the CertificateLocalizationService to keep the track
    // of the certificates sent by the users
    certLocService = new CertificateLocalizationService(CertificateLocalizationService.ServiceType.HM)
    certLocService.init(new Configuration())
    certLocService.start()
    CertificateLocalizationCtx.getInstance.setCertificateLocalization(certLocService)

    // Add shutdown hook to shutdown the CertificateLocalizationService
    shutdownHookMgr = ShutdownHookManager.get
    shutdownHookMgr.addShutdownHook(new Runnable {
      override def run(): Unit = certLocService.stop
    }, 10)
  }

  def setCrypto(keyStore: ByteBuffer, trustStore: ByteBuffer, password: String) {
    val username = UserGroupInformation.getCurrentUser.getUserName
    val applicationId = UserGroupInformation.getCurrentUser.getApplicationId
    CertificateLocalizationCtx.getInstance.getCertificateLocalization.materializeCertificates(username, applicationId, username, keyStore, password, trustStore, password)
  }
}
