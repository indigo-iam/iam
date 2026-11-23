-- MySQL dump 10.13  Distrib 8.3.0, for Linux (x86_64)
--
-- Host: db    Database: iam
-- ------------------------------------------------------
-- Server version	8.3.0

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `SPRING_SESSION`
--

DROP TABLE IF EXISTS `SPRING_SESSION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `SPRING_SESSION` (
  `PRIMARY_ID` char(36) NOT NULL,
  `SESSION_ID` char(36) NOT NULL,
  `CREATION_TIME` bigint NOT NULL,
  `LAST_ACCESS_TIME` bigint NOT NULL,
  `MAX_INACTIVE_INTERVAL` int NOT NULL,
  `EXPIRY_TIME` bigint NOT NULL,
  `PRINCIPAL_NAME` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`PRIMARY_ID`),
  UNIQUE KEY `SPRING_SESSION_IX1` (`SESSION_ID`),
  KEY `SPRING_SESSION_IX2` (`EXPIRY_TIME`),
  KEY `SPRING_SESSION_IX3` (`PRINCIPAL_NAME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SPRING_SESSION`
--

LOCK TABLES `SPRING_SESSION` WRITE;
/*!40000 ALTER TABLE `SPRING_SESSION` DISABLE KEYS */;
/*!40000 ALTER TABLE `SPRING_SESSION` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SPRING_SESSION_ATTRIBUTES`
--

DROP TABLE IF EXISTS `SPRING_SESSION_ATTRIBUTES`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `SPRING_SESSION_ATTRIBUTES` (
  `SESSION_PRIMARY_ID` char(36) NOT NULL,
  `ATTRIBUTE_NAME` varchar(200) NOT NULL,
  `ATTRIBUTE_BYTES` blob NOT NULL,
  PRIMARY KEY (`SESSION_PRIMARY_ID`,`ATTRIBUTE_NAME`),
  CONSTRAINT `SPRING_SESSION_ATTRIBUTES_FK` FOREIGN KEY (`SESSION_PRIMARY_ID`) REFERENCES `SPRING_SESSION` (`PRIMARY_ID`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SPRING_SESSION_ATTRIBUTES`
--

LOCK TABLES `SPRING_SESSION_ATTRIBUTES` WRITE;
/*!40000 ALTER TABLE `SPRING_SESSION_ATTRIBUTES` DISABLE KEYS */;
/*!40000 ALTER TABLE `SPRING_SESSION_ATTRIBUTES` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `access_token`
--

DROP TABLE IF EXISTS `access_token`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `access_token` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `token_value` varchar(4096) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  `token_type` varchar(256) DEFAULT NULL,
  `refresh_token_id` bigint DEFAULT NULL,
  `client_id` bigint DEFAULT NULL,
  `auth_holder_id` bigint DEFAULT NULL,
  `id_token_id` bigint DEFAULT NULL,
  `approved_site_id` bigint DEFAULT NULL,
  `token_value_hash` char(64) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `at_tvh_idx` (`token_value_hash`),
  KEY `at_exp_idx` (`expiration`),
  KEY `at_ahi_idx` (`auth_holder_id`),
  KEY `FK_access_token_client_id` (`client_id`),
  KEY `FK_access_token_refresh_token_id` (`refresh_token_id`),
  CONSTRAINT `FK_access_token_auth_holder_id` FOREIGN KEY (`auth_holder_id`) REFERENCES `authentication_holder` (`id`) ON DELETE CASCADE,
  CONSTRAINT `FK_access_token_client_id` FOREIGN KEY (`client_id`) REFERENCES `client_details` (`id`) ON DELETE CASCADE,
  CONSTRAINT `FK_access_token_refresh_token_id` FOREIGN KEY (`refresh_token_id`) REFERENCES `refresh_token` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `access_token`
--

LOCK TABLES `access_token` WRITE;
/*!40000 ALTER TABLE `access_token` DISABLE KEYS */;
INSERT INTO `access_token` VALUES (1,'{\"wlcg.ver\":\"1.0\",\"sub\":\"73f16d93-2441-4a50-88ff-85360d78c6b5\",\"aud\":\"https://wlcg.cern.ch/jwt/v1/any\",\"nbf\":1795444921,\"scope\":\"openid profile email offline_access phone storage.create:/ storage.modify:/ storage.read:/ storage.stage:/ iam:admin.read iam:admin.write\",\"auth_time\":1795444940,\"iss\":\"https://iam.local.io/\",\"exp\":1795448581,\"iat\":1795444981,\"jti\":\"3317f9c9-6eae-48d8-8a0a-ab90f4b3bc1c\",\"client_id\":\"client\"}','2026-11-23 15:43:02','Bearer',1,1,2,NULL,NULL,'e603a0722b6c842935168299ef15a9ab438d70bb5e82eb1cea56841aa84af9b8'),(2,'{\"wlcg.ver\":\"1.0\",\"sub\":\"80e5fb8d-b7c8-451a-89ba-346ae278a66f\",\"aud\":\"https://wlcg.cern.ch/jwt/v1/any\",\"nbf\":1795445935,\"scope\":\"openid profile email offline_access phone storage.create:/ storage.modify:/ storage.read:/ storage.stage:/\",\"auth_time\":1795445919,\"iss\":\"https://iam.local.io/\",\"exp\":1795449595,\"iat\":1795445995,\"jti\":\"a48f4fc0-3503-4d7c-a31f-e239fb7483e4\",\"client_id\":\"client\"}','2026-11-23 15:59:56','Bearer',2,1,4,NULL,NULL,'8a23ea92ae4706b4cbdd500a41e1430a2a6a1d968e01106329003636aafcd45c'),(3,'{\"wlcg.ver\":\"1.0\",\"sub\":\"admin-client-rw\",\"aud\":\"https://wlcg.cern.ch/jwt/v1/any\",\"nbf\":1795452279,\"scope\":\"iam:admin.read iam:admin.write\",\"iss\":\"https://iam.local.io/\",\"exp\":1795455939,\"iat\":1795452339,\"jti\":\"b596d6fa-a120-4385-8668-4a8bdee30b44\",\"client_id\":\"admin-client-rw\"}','2026-11-23 17:45:39','Bearer',NULL,18,5,NULL,NULL,'e9e2bd8996ad573b3d2676f57daa427f9073e554780a85567298f8a3437964fe'),(4,'{\"wlcg.ver\":\"1.0\",\"sub\":\"80e5fb8d-b7c8-451a-89ba-346ae278a66f\",\"aud\":\"https://wlcg.cern.ch/jwt/v1/any\",\"nbf\":1795452297,\"scope\":\"storage.read:/pippo\",\"auth_time\":1795446088,\"iss\":\"https://iam.local.io/\",\"exp\":1795455957,\"iat\":1795452357,\"jti\":\"636c4f66-4515-4505-8a92-e510ff0080c7\",\"client_id\":\"client\"}','2026-11-23 17:45:58','Bearer',2,1,4,NULL,NULL,'6ef945407e20e8460681d7deba01a65951bbcce324fdbcd149e8212425653354'),(5,'{\"wlcg.ver\":\"1.0\",\"sub\":\"73f16d93-2441-4a50-88ff-85360d78c6b5\",\"aud\":\"https://wlcg.cern.ch/jwt/v1/any\",\"nbf\":1795452675,\"scope\":\"openid iam:admin.read\",\"auth_time\":1795452733,\"iss\":\"https://iam.local.io/\",\"exp\":1798032735,\"iat\":1795452735,\"jti\":\"93440fb9-986f-42b3-8946-2c79456cbb0f\",\"client_id\":\"client\"}','2026-12-23 13:32:15','Bearer',NULL,1,7,NULL,NULL,'4e7d0d556c6c29dc725d76e30a136b5fd49384a991f90c2025f0441061c1ee44');
/*!40000 ALTER TABLE `access_token` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `access_token_permissions`
--

DROP TABLE IF EXISTS `access_token_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `access_token_permissions` (
  `access_token_id` bigint NOT NULL,
  `permission_id` bigint NOT NULL,
  PRIMARY KEY (`access_token_id`,`permission_id`),
  KEY `FK_access_token_permissions_permission_id` (`permission_id`),
  CONSTRAINT `FK_access_token_permissions_access_token_id` FOREIGN KEY (`access_token_id`) REFERENCES `access_token` (`id`) ON DELETE CASCADE,
  CONSTRAINT `FK_access_token_permissions_permission_id` FOREIGN KEY (`permission_id`) REFERENCES `permission` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `access_token_permissions`
--

LOCK TABLES `access_token_permissions` WRITE;
/*!40000 ALTER TABLE `access_token_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `access_token_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `address`
--

DROP TABLE IF EXISTS `address`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `address` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `formatted` varchar(256) DEFAULT NULL,
  `street_address` varchar(256) DEFAULT NULL,
  `locality` varchar(256) DEFAULT NULL,
  `region` varchar(256) DEFAULT NULL,
  `postal_code` varchar(256) DEFAULT NULL,
  `country` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `address`
--

LOCK TABLES `address` WRITE;
/*!40000 ALTER TABLE `address` DISABLE KEYS */;
/*!40000 ALTER TABLE `address` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `approved_site`
--

DROP TABLE IF EXISTS `approved_site`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `approved_site` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` varchar(256) DEFAULT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  `creation_date` timestamp NULL DEFAULT NULL,
  `access_date` timestamp NULL DEFAULT NULL,
  `timeout_date` timestamp NULL DEFAULT NULL,
  `whitelisted_site_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_approved_site_client_id` (`client_id`),
  CONSTRAINT `FK_approved_site_client_id` FOREIGN KEY (`client_id`) REFERENCES `client_details` (`client_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `approved_site`
--

LOCK TABLES `approved_site` WRITE;
/*!40000 ALTER TABLE `approved_site` DISABLE KEYS */;
/*!40000 ALTER TABLE `approved_site` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `approved_site_scope`
--

DROP TABLE IF EXISTS `approved_site_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `approved_site_scope` (
  `owner_id` bigint DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL,
  KEY `FK_approved_site_scope_owner_id` (`owner_id`),
  CONSTRAINT `FK_approved_site_scope_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `approved_site` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `approved_site_scope`
--

LOCK TABLES `approved_site_scope` WRITE;
/*!40000 ALTER TABLE `approved_site_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `approved_site_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder`
--

DROP TABLE IF EXISTS `authentication_holder`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_auth_id` bigint DEFAULT NULL,
  `approved` tinyint(1) DEFAULT NULL,
  `redirect_uri` varchar(2048) DEFAULT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_authentication_holder_user_auth_id` (`user_auth_id`),
  KEY `FK_authentication_holder_client_id` (`client_id`),
  CONSTRAINT `FK_authentication_holder_client_id` FOREIGN KEY (`client_id`) REFERENCES `client_details` (`client_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `FK_authentication_holder_user_auth_id` FOREIGN KEY (`user_auth_id`) REFERENCES `saved_user_auth` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder`
--

LOCK TABLES `authentication_holder` WRITE;
/*!40000 ALTER TABLE `authentication_holder` DISABLE KEYS */;
INSERT INTO `authentication_holder` VALUES (1,1,1,'https://iam.local.io/iam-test-client/openid_connect_login','client'),(2,2,1,'https://iam.local.io/iam-test-client/openid_connect_login','client'),(3,3,1,'https://iam.local.io/iam-test-client/openid_connect_login','client'),(4,4,1,'https://iam.local.io/iam-test-client/openid_connect_login','client');
/*!40000 ALTER TABLE `authentication_holder` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_authority`
--

DROP TABLE IF EXISTS `authentication_holder_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_authority` (
  `owner_id` bigint DEFAULT NULL,
  `authority` varchar(256) DEFAULT NULL,
  KEY `aha_oi_idx` (`owner_id`),
  CONSTRAINT `FK_authentication_holder_authority_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `authentication_holder` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_authority`
--

LOCK TABLES `authentication_holder_authority` WRITE;
/*!40000 ALTER TABLE `authentication_holder_authority` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_extension`
--

DROP TABLE IF EXISTS `authentication_holder_extension`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_extension` (
  `owner_id` bigint DEFAULT NULL,
  `extension` varchar(2048) DEFAULT NULL,
  `val` varchar(2048) DEFAULT NULL,
  KEY `ahe_oi_idx` (`owner_id`),
  CONSTRAINT `FK_authentication_holder_extension_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `authentication_holder` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_extension`
--

LOCK TABLES `authentication_holder_extension` WRITE;
/*!40000 ALTER TABLE `authentication_holder_extension` DISABLE KEYS */;
INSERT INTO `authentication_holder_extension` VALUES (1,'amr','[\"pwd\"]'),(1,'consent_transaction_id','7efc591e-810c-45f2-9095-88a8df4ed98e'),(1,'nonce','230898b39321e'),(1,'AUTH_TIMESTAMP','1795444940097'),(2,'amr','[\"pwd\"]'),(2,'consent_transaction_id','7efc591e-810c-45f2-9095-88a8df4ed98e'),(2,'nonce','230898b39321e'),(2,'AUTH_TIMESTAMP','1795444940097'),(3,'amr','[\"pwd\"]'),(3,'consent_transaction_id','7f563afb-6c11-406c-a3e3-24c0d4ba2dcf'),(3,'nonce','28d5fedc55d76'),(3,'AUTH_TIMESTAMP','1795445919494'),(4,'amr','[\"pwd\"]'),(4,'consent_transaction_id','7f563afb-6c11-406c-a3e3-24c0d4ba2dcf'),(4,'nonce','28d5fedc55d76'),(4,'AUTH_TIMESTAMP','1795445919494');
/*!40000 ALTER TABLE `authentication_holder_extension` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_request_parameter`
--

DROP TABLE IF EXISTS `authentication_holder_request_parameter`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_request_parameter` (
  `owner_id` bigint DEFAULT NULL,
  `param` varchar(2048) DEFAULT NULL,
  `val` varchar(2048) DEFAULT NULL,
  KEY `ahrp_oi_idx` (`owner_id`),
  CONSTRAINT `FK_authentication_holder_request_parameter_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `authentication_holder` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_request_parameter`
--

LOCK TABLES `authentication_holder_request_parameter` WRITE;
/*!40000 ALTER TABLE `authentication_holder_request_parameter` DISABLE KEYS */;
INSERT INTO `authentication_holder_request_parameter` VALUES (1,'scope','openid profile email offline_access phone storage.create:/ storage.modify:/ storage.read:/ storage.stage:/ iam:admin.read iam:admin.write'),(1,'amr','[\"pwd\"]'),(1,'response_type','code'),(1,'redirect_uri','https://iam.local.io/iam-test-client/openid_connect_login'),(1,'state','8880559f9ea4'),(1,'nonce','230898b39321e'),(1,'client_id','client'),(2,'code','ZJFQTazFhvxqzn0C8JL1Z1JLiwfXnYdYSYRkXUbh83E'),(2,'grant_type','authorization_code'),(2,'scope','openid profile email offline_access phone storage.create:/ storage.modify:/ storage.read:/ storage.stage:/ iam:admin.read iam:admin.write'),(2,'amr','[\"pwd\"]'),(2,'response_type','code'),(2,'state','8880559f9ea4'),(2,'redirect_uri','https://iam.local.io/iam-test-client/openid_connect_login'),(2,'nonce','230898b39321e'),(2,'client_id','client'),(3,'scope','openid profile email offline_access phone storage.create:/ storage.modify:/ storage.read:/ storage.stage:/'),(3,'amr','[\"pwd\"]'),(3,'response_type','code'),(3,'redirect_uri','https://iam.local.io/iam-test-client/openid_connect_login'),(3,'state','202b4f0210689'),(3,'nonce','28d5fedc55d76'),(3,'client_id','client'),(4,'code','OBL0jEQOKe7QafWB_DzrOLbNoa2QoW2XUBXsGX2nqX0'),(4,'grant_type','authorization_code'),(4,'scope','openid profile email offline_access phone storage.create:/ storage.modify:/ storage.read:/ storage.stage:/'),(4,'amr','[\"pwd\"]'),(4,'response_type','code'),(4,'state','202b4f0210689'),(4,'redirect_uri','https://iam.local.io/iam-test-client/openid_connect_login'),(4,'nonce','28d5fedc55d76'),(4,'client_id','client');
/*!40000 ALTER TABLE `authentication_holder_request_parameter` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_resource_id`
--

DROP TABLE IF EXISTS `authentication_holder_resource_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_resource_id` (
  `owner_id` bigint DEFAULT NULL,
  `resource_id` varchar(2048) DEFAULT NULL,
  KEY `ahri_oi_idx` (`owner_id`),
  CONSTRAINT `FK_authentication_holder_resource_id_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `authentication_holder` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_resource_id`
--

LOCK TABLES `authentication_holder_resource_id` WRITE;
/*!40000 ALTER TABLE `authentication_holder_resource_id` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder_resource_id` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_response_type`
--

DROP TABLE IF EXISTS `authentication_holder_response_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_response_type` (
  `owner_id` bigint DEFAULT NULL,
  `response_type` varchar(2048) DEFAULT NULL,
  KEY `ahrt_oi_idx` (`owner_id`),
  CONSTRAINT `FK_authentication_holder_response_type_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `authentication_holder` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_response_type`
--

LOCK TABLES `authentication_holder_response_type` WRITE;
/*!40000 ALTER TABLE `authentication_holder_response_type` DISABLE KEYS */;
INSERT INTO `authentication_holder_response_type` VALUES (1,'code'),(2,'code'),(3,'code'),(4,'code');
/*!40000 ALTER TABLE `authentication_holder_response_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_scope`
--

DROP TABLE IF EXISTS `authentication_holder_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `authentication_holder_scope` (
  `owner_id` bigint DEFAULT NULL,
  `scope` varchar(2048) DEFAULT NULL,
  KEY `ahs_oi_idx` (`owner_id`),
  CONSTRAINT `FK_authentication_holder_scope_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `authentication_holder` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_scope`
--

LOCK TABLES `authentication_holder_scope` WRITE;
/*!40000 ALTER TABLE `authentication_holder_scope` DISABLE KEYS */;
INSERT INTO `authentication_holder_scope` VALUES (1,'storage.create:/'),(1,'phone'),(1,'openid'),(1,'offline_access'),(1,'profile'),(1,'storage.read:/'),(1,'iam:admin.read'),(1,'storage.stage:/'),(1,'iam:admin.write'),(1,'storage.modify:/'),(1,'email'),(2,'storage.create:/'),(2,'phone'),(2,'openid'),(2,'offline_access'),(2,'profile'),(2,'storage.read:/'),(2,'iam:admin.read'),(2,'storage.stage:/'),(2,'iam:admin.write'),(2,'storage.modify:/'),(2,'email'),(3,'storage.create:/'),(3,'phone'),(3,'openid'),(3,'offline_access'),(3,'profile'),(3,'storage.read:/'),(3,'storage.stage:/'),(3,'storage.modify:/'),(3,'email'),(4,'storage.create:/'),(4,'phone'),(4,'openid'),(4,'offline_access'),(4,'profile'),(4,'storage.read:/'),(4,'storage.stage:/'),(4,'storage.modify:/'),(4,'email');
/*!40000 ALTER TABLE `authentication_holder_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authorization_code`
--

DROP TABLE IF EXISTS `authorization_code`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `authorization_code` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `code` varchar(256) DEFAULT NULL,
  `auth_holder_id` bigint DEFAULT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ac_ahi_idx` (`auth_holder_id`),
  CONSTRAINT `FK_authorization_code_auth_holder_id` FOREIGN KEY (`auth_holder_id`) REFERENCES `authentication_holder` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authorization_code`
--

LOCK TABLES `authorization_code` WRITE;
/*!40000 ALTER TABLE `authorization_code` DISABLE KEYS */;
/*!40000 ALTER TABLE `authorization_code` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `blacklisted_site`
--

DROP TABLE IF EXISTS `blacklisted_site`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `blacklisted_site` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `uri` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `blacklisted_site`
--

LOCK TABLES `blacklisted_site` WRITE;
/*!40000 ALTER TABLE `blacklisted_site` DISABLE KEYS */;
/*!40000 ALTER TABLE `blacklisted_site` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claim`
--

DROP TABLE IF EXISTS `claim`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `claim` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(256) DEFAULT NULL,
  `friendly_name` varchar(1024) DEFAULT NULL,
  `claim_type` varchar(1024) DEFAULT NULL,
  `claim_value` varchar(1024) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claim`
--

LOCK TABLES `claim` WRITE;
/*!40000 ALTER TABLE `claim` DISABLE KEYS */;
/*!40000 ALTER TABLE `claim` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claim_issuer`
--

DROP TABLE IF EXISTS `claim_issuer`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `claim_issuer` (
  `owner_id` bigint NOT NULL,
  `issuer` varchar(1024) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claim_issuer`
--

LOCK TABLES `claim_issuer` WRITE;
/*!40000 ALTER TABLE `claim_issuer` DISABLE KEYS */;
/*!40000 ALTER TABLE `claim_issuer` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claim_to_permission_ticket`
--

DROP TABLE IF EXISTS `claim_to_permission_ticket`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `claim_to_permission_ticket` (
  `permission_ticket_id` bigint NOT NULL,
  `claim_id` bigint NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claim_to_permission_ticket`
--

LOCK TABLES `claim_to_permission_ticket` WRITE;
/*!40000 ALTER TABLE `claim_to_permission_ticket` DISABLE KEYS */;
/*!40000 ALTER TABLE `claim_to_permission_ticket` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claim_to_policy`
--

DROP TABLE IF EXISTS `claim_to_policy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `claim_to_policy` (
  `policy_id` bigint NOT NULL,
  `claim_id` bigint NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claim_to_policy`
--

LOCK TABLES `claim_to_policy` WRITE;
/*!40000 ALTER TABLE `claim_to_policy` DISABLE KEYS */;
/*!40000 ALTER TABLE `claim_to_policy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `claim_token_format`
--

DROP TABLE IF EXISTS `claim_token_format`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `claim_token_format` (
  `owner_id` bigint NOT NULL,
  `claim_token_format` varchar(1024) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `claim_token_format`
--

LOCK TABLES `claim_token_format` WRITE;
/*!40000 ALTER TABLE `claim_token_format` DISABLE KEYS */;
/*!40000 ALTER TABLE `claim_token_format` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_authority`
--

DROP TABLE IF EXISTS `client_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_authority` (
  `owner_id` bigint DEFAULT NULL,
  `authority` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_authority`
--

LOCK TABLES `client_authority` WRITE;
/*!40000 ALTER TABLE `client_authority` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_claims_redirect_uri`
--

DROP TABLE IF EXISTS `client_claims_redirect_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_claims_redirect_uri` (
  `owner_id` bigint DEFAULT NULL,
  `redirect_uri` varchar(2048) DEFAULT NULL,
  KEY `FK_client_claims_redirect_uri_owner_id` (`owner_id`),
  CONSTRAINT `FK_client_claims_redirect_uri_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `client_details` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_claims_redirect_uri`
--

LOCK TABLES `client_claims_redirect_uri` WRITE;
/*!40000 ALTER TABLE `client_claims_redirect_uri` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_claims_redirect_uri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_contact`
--

DROP TABLE IF EXISTS `client_contact`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_contact` (
  `owner_id` bigint DEFAULT NULL,
  `contact` varchar(256) DEFAULT NULL,
  KEY `FK_client_contact_owner_id` (`owner_id`),
  CONSTRAINT `FK_client_contact_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `client_details` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_contact`
--

LOCK TABLES `client_contact` WRITE;
/*!40000 ALTER TABLE `client_contact` DISABLE KEYS */;
INSERT INTO `client_contact` VALUES (1,'admin@example.com'),(12,'test@example.com');
/*!40000 ALTER TABLE `client_contact` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_default_acr_value`
--

DROP TABLE IF EXISTS `client_default_acr_value`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_default_acr_value` (
  `owner_id` bigint DEFAULT NULL,
  `default_acr_value` varchar(2000) DEFAULT NULL,
  KEY `FK_client_default_acr_value_owner_id` (`owner_id`),
  CONSTRAINT `FK_client_default_acr_value_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `client_details` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_default_acr_value`
--

LOCK TABLES `client_default_acr_value` WRITE;
/*!40000 ALTER TABLE `client_default_acr_value` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_default_acr_value` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_details`
--

DROP TABLE IF EXISTS `client_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_details` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `client_description` varchar(1024) DEFAULT NULL,
  `reuse_refresh_tokens` tinyint(1) NOT NULL DEFAULT '1',
  `dynamically_registered` tinyint(1) NOT NULL DEFAULT '0',
  `allow_introspection` tinyint(1) NOT NULL DEFAULT '0',
  `id_token_validity_seconds` bigint NOT NULL DEFAULT '600',
  `client_id` varchar(256) DEFAULT NULL,
  `client_secret` text,
  `access_token_validity_seconds` bigint DEFAULT NULL,
  `refresh_token_validity_seconds` bigint DEFAULT NULL,
  `application_type` varchar(256) DEFAULT NULL,
  `client_name` varchar(256) DEFAULT NULL,
  `token_endpoint_auth_method` varchar(256) DEFAULT NULL,
  `subject_type` varchar(256) DEFAULT NULL,
  `logo_uri` text,
  `policy_uri` text,
  `client_uri` text,
  `tos_uri` text,
  `jwks_uri` text,
  `jwks` text,
  `sector_identifier_uri` text,
  `request_object_signing_alg` varchar(256) DEFAULT NULL,
  `user_info_signed_response_alg` varchar(256) DEFAULT NULL,
  `user_info_encrypted_response_alg` varchar(256) DEFAULT NULL,
  `user_info_encrypted_response_enc` varchar(256) DEFAULT NULL,
  `id_token_signed_response_alg` varchar(256) DEFAULT NULL,
  `id_token_encrypted_response_alg` varchar(256) DEFAULT NULL,
  `id_token_encrypted_response_enc` varchar(256) DEFAULT NULL,
  `token_endpoint_auth_signing_alg` varchar(256) DEFAULT NULL,
  `default_max_age` bigint DEFAULT NULL,
  `require_auth_time` tinyint(1) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `initiate_login_uri` varchar(2048) DEFAULT NULL,
  `clear_access_tokens_on_refresh` tinyint(1) NOT NULL DEFAULT '1',
  `software_statement` text,
  `code_challenge_method` varchar(256) DEFAULT NULL,
  `software_id` text,
  `software_version` text,
  `device_code_validity_seconds` bigint DEFAULT NULL,
  `active` tinyint(1) DEFAULT '1',
  `status_changed_on` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `status_changed_by` varchar(36) DEFAULT NULL,
  `up_scoping_enabled` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `client_id` (`client_id`),
  KEY `cd_ci_idx` (`client_id`)
) ENGINE=InnoDB AUTO_INCREMENT=28 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_details`
--

LOCK TABLES `client_details` WRITE;
/*!40000 ALTER TABLE `client_details` DISABLE KEYS */;
INSERT INTO `client_details` VALUES (1,NULL,1,0,1,600,'client','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,0,NULL,'Test Client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,600,1,NULL,NULL,1),(2,NULL,1,0,1,0,'tasks-app','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',0,NULL,NULL,'Tasks App','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(3,NULL,1,0,1,600,'post-client','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Post client','SECRET_POST',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(4,NULL,1,0,1,600,'client-cred','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Client credentials','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(5,NULL,1,0,1,600,'password-grant','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Password grant client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(6,NULL,1,0,1,600,'scim-client-ro','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'SCIM client (read-only)','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,600,1,'2026-11-23 14:41:08',NULL,1),(7,NULL,1,0,1,600,'scim-client-rw','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'SCIM client (read-write)','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,600,1,'2026-11-23 14:41:08',NULL,1),(8,NULL,1,0,1,600,'token-exchange-actor','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Token Exchange grant client actor','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(9,NULL,1,0,1,600,'token-exchange-subject','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Token Exchange grant client subject','SECRET_POST',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(10,NULL,1,0,1,600,'registration-client','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Registration service test client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(11,NULL,1,0,1,600,'token-lookup-client','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Token lookup client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(12,NULL,1,0,1,600,'device-code-client','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Device code client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,600,1,'2026-11-23 14:41:08',NULL,1),(13,'Consent client description',1,0,0,600,'consent-client',NULL,3600,86400,NULL,'Consent Client','NONE',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,600,1,'2026-11-23 14:41:08',NULL,1),(14,NULL,1,0,0,600,'public-dc-client',NULL,3600,86400,NULL,'Public Device Code client','NONE',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,600,1,'2026-11-23 14:41:08',NULL,1),(15,NULL,1,0,1,600,'jwt-auth-client_secret_jwt','tcvWUomdqtf55IV3MGOWNX6s6RG6crU2tiyeS/U7Fss=',3600,86400,NULL,'JWT Bearer Auth Client (client_secret_jwt)','SECRET_JWT',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'HS256',NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(16,NULL,1,0,1,600,'jwt-auth-private_key_jwt','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'JWT Bearer Auth Client (private_key_jwt)','PRIVATE_KEY',NULL,NULL,NULL,NULL,NULL,NULL,'{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"rsa1\",\"n\":\"1y1CP181zqPNPlV1JDM7Xv0QnGswhSTHe8_XPZHxDTJkykpk_1BmgA3ovP62QRE2ORgsv5oSBI_Z_RaOc4Zx2FonjEJF2oBHtBjsAiF-pxGkM5ZPjFNgFTGp1yUUBjFDcEeIGCwPEyYSt93sQIP_0DRbViMUnpyn3xgM_a1dO5brEWR2n1Uqff1yA5NXfLS03qpl2dpH4HFY5-Zs4bvtJykpAOhoHuIQbz-hmxb9MZ3uTAwsx2HiyEJtz-suyTBHO3BM2o8UcCeyfa34ShPB8i86-sf78fOk2KeRIW1Bju3ANmdV3sxL0j29cesxKCZ06u2ZiGR3Srbft8EdLPzf-w\"}]}',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'RS256',NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(17,NULL,1,0,1,600,'admin-client-ro','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Admin client (read-only)','SECRET_POST',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(18,NULL,1,0,1,600,'admin-client-rw','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Admin client (read-write)','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(19,NULL,1,0,1,600,'public-client',NULL,3600,3600,NULL,'Public client','NONE',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1),(20,NULL,1,0,1,600,'refresh-client','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,36000,NULL,'Refresh Flow client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,30,1,'2026-11-23 14:41:08',NULL,1),(21,NULL,1,0,1,0,'protected-resource','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',0,0,NULL,'Protected Resource allowed only to introspect','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,0,1,'2026-11-23 14:41:08',NULL,1),(22,NULL,1,0,1,0,'whitelist-client','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',0,0,NULL,'Client which is not requiring confirmation access','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,0,1,'2026-11-23 14:41:08',NULL,1),(23,NULL,1,0,0,600,'public-client-with-secret','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,3600,NULL,'Public client with secret','NONE',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,600,1,'2026-11-23 14:41:08',NULL,1),(24,NULL,1,0,0,600,'pkce-s256-client','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,3600,NULL,'Client with PKCE S256','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'S256',NULL,NULL,600,1,'2026-11-23 14:41:08',NULL,1),(25,NULL,1,0,0,600,'pkce-plain-client','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,3600,NULL,'Client with PKCE plain','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'plain',NULL,NULL,600,1,'2026-11-23 14:41:08',NULL,1),(26,NULL,1,0,0,600,'pkce-none-client','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,3600,NULL,'Client with PKCE none','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'none',NULL,NULL,600,1,'2026-11-23 14:41:08',NULL,1),(27,NULL,1,0,1,600,'https://federated-client.com','K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=',3600,86400,NULL,'Federated client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,'2026-11-23 14:41:08',NULL,1,NULL,'optional',NULL,NULL,NULL,1,'2026-11-23 14:41:08',NULL,1);
/*!40000 ALTER TABLE `client_details` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_grant_type`
--

DROP TABLE IF EXISTS `client_grant_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_grant_type` (
  `owner_id` bigint DEFAULT NULL,
  `grant_type` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_grant_type`
--

LOCK TABLES `client_grant_type` WRITE;
/*!40000 ALTER TABLE `client_grant_type` DISABLE KEYS */;
INSERT INTO `client_grant_type` VALUES (1,'authorization_code'),(1,'urn:ietf:params:oauth:grant_type:redelegate'),(1,'password'),(1,'refresh_token'),(3,'authorization_code'),(3,'client_credentials'),(3,'refresh_token'),(3,'password'),(4,'password'),(4,'client_credentials'),(5,'password'),(5,'authorization_code'),(5,'refresh_token'),(6,'client_credentials'),(6,'password'),(7,'client_credentials'),(7,'password'),(7,'refresh_token'),(7,'urn:ietf:params:oauth:grant-type:device_code'),(8,'urn:ietf:params:oauth:grant-type:token-exchange'),(8,'client_credentials'),(8,'password'),(8,'refresh_token'),(9,'password'),(9,'refresh_token'),(9,'client_credentials'),(10,'client_credentials'),(10,'refresh_token'),(11,'authorization_code'),(11,'refresh_token'),(11,'password'),(11,'client_credentials'),(11,'urn:ietf:params:oauth:grant-type:token-exchange'),(12,'refresh_token'),(12,'urn:ietf:params:oauth:grant-type:device_code'),(13,'authorization_code'),(14,'urn:ietf:params:oauth:grant-type:device_code'),(15,'client_credentials'),(16,'client_credentials'),(17,'client_credentials'),(17,'urn:ietf:params:oauth:grant-type:device_code'),(17,'authorization_code'),(17,'password'),(18,'client_credentials'),(18,'urn:ietf:params:oauth:grant-type:device_code'),(18,'authorization_code'),(18,'password'),(19,'client_credentials'),(20,'authorization_code'),(20,'password'),(20,'refresh_token'),(20,'urn:ietf:params:oauth:grant-type:device_code'),(22,'authorization_code'),(23,'client_credentials'),(24,'authorization_code'),(24,'urn:ietf:params:oauth:grant-type:device_code'),(25,'authorization_code'),(26,'authorization_code'),(27,'client_credentials');
/*!40000 ALTER TABLE `client_grant_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_last_used`
--

DROP TABLE IF EXISTS `client_last_used`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_last_used` (
  `client_details_id` bigint NOT NULL,
  `last_used` date NOT NULL,
  PRIMARY KEY (`client_details_id`),
  CONSTRAINT `fk_client_last_used` FOREIGN KEY (`client_details_id`) REFERENCES `client_details` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_last_used`
--

LOCK TABLES `client_last_used` WRITE;
/*!40000 ALTER TABLE `client_last_used` DISABLE KEYS */;
INSERT INTO `client_last_used` VALUES (1,'1994-03-21'),(2,'1994-03-20'),(3,'1994-03-19'),(4,'1994-03-23');
/*!40000 ALTER TABLE `client_last_used` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_post_logout_redirect_uri`
--

DROP TABLE IF EXISTS `client_post_logout_redirect_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_post_logout_redirect_uri` (
  `owner_id` bigint DEFAULT NULL,
  `post_logout_redirect_uri` varchar(2000) DEFAULT NULL,
  KEY `FK_client_post_logout_redirect_uri_owner_id` (`owner_id`),
  CONSTRAINT `FK_client_post_logout_redirect_uri_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `client_details` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_post_logout_redirect_uri`
--

LOCK TABLES `client_post_logout_redirect_uri` WRITE;
/*!40000 ALTER TABLE `client_post_logout_redirect_uri` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_post_logout_redirect_uri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_redirect_uri`
--

DROP TABLE IF EXISTS `client_redirect_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_redirect_uri` (
  `owner_id` bigint DEFAULT NULL,
  `redirect_uri` varchar(2048) DEFAULT NULL,
  KEY `FK_client_redirect_uri_owner_id` (`owner_id`),
  CONSTRAINT `FK_client_redirect_uri_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `client_details` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_redirect_uri`
--

LOCK TABLES `client_redirect_uri` WRITE;
/*!40000 ALTER TABLE `client_redirect_uri` DISABLE KEYS */;
INSERT INTO `client_redirect_uri` VALUES (1,'http://localhost:9090/iam-test-client/openid_connect_login'),(1,'https://iam.local.io/iam-test-client/openid_connect_login'),(1,'http://localhost:9090/iam-test-client/login/oauth2/code/dynamic'),(3,'http://localhost:4000/callback'),(4,'http://localhost:5000/callback'),(11,'http://localhost:1234/callback'),(13,'http://localhost:9876/callback'),(18,'https://iam.local.io/iam-test-client/openid_connect_login'),(20,'http://localhost:4000/callback'),(22,'http://localhost:1234/callback'),(24,'https://iam.local.io/iam-test-client/openid_connect_login'),(25,'https://iam.local.io/iam-test-client/openid_connect_login'),(26,'https://iam.local.io/iam-test-client/openid_connect_login');
/*!40000 ALTER TABLE `client_redirect_uri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_relying_party`
--

DROP TABLE IF EXISTS `client_relying_party`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_relying_party` (
  `client_details_id` bigint NOT NULL,
  `expiration` timestamp NOT NULL,
  `entity_id` varchar(512) NOT NULL,
  PRIMARY KEY (`client_details_id`),
  CONSTRAINT `fk_client_expiration` FOREIGN KEY (`client_details_id`) REFERENCES `client_details` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_relying_party`
--

LOCK TABLES `client_relying_party` WRITE;
/*!40000 ALTER TABLE `client_relying_party` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_relying_party` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_request_uri`
--

DROP TABLE IF EXISTS `client_request_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_request_uri` (
  `owner_id` bigint DEFAULT NULL,
  `request_uri` varchar(2000) DEFAULT NULL,
  KEY `FK_client_request_uri_owner_id` (`owner_id`),
  CONSTRAINT `FK_client_request_uri_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `client_details` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_request_uri`
--

LOCK TABLES `client_request_uri` WRITE;
/*!40000 ALTER TABLE `client_request_uri` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_request_uri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_resource`
--

DROP TABLE IF EXISTS `client_resource`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_resource` (
  `owner_id` bigint DEFAULT NULL,
  `resource_id` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_resource`
--

LOCK TABLES `client_resource` WRITE;
/*!40000 ALTER TABLE `client_resource` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_resource` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_response_type`
--

DROP TABLE IF EXISTS `client_response_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_response_type` (
  `owner_id` bigint DEFAULT NULL,
  `response_type` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_response_type`
--

LOCK TABLES `client_response_type` WRITE;
/*!40000 ALTER TABLE `client_response_type` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_response_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_scope`
--

DROP TABLE IF EXISTS `client_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_scope` (
  `owner_id` bigint DEFAULT NULL,
  `scope` varchar(2048) DEFAULT NULL,
  KEY `FK_client_scope_owner_id` (`owner_id`),
  CONSTRAINT `FK_client_scope_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `client_details` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_scope`
--

LOCK TABLES `client_scope` WRITE;
/*!40000 ALTER TABLE `client_scope` DISABLE KEYS */;
INSERT INTO `client_scope` VALUES (1,'openid'),(1,'profile'),(1,'email'),(1,'address'),(1,'phone'),(1,'offline_access'),(1,'read-tasks'),(1,'write-tasks'),(1,'read:/'),(1,'write:/'),(1,'attr'),(1,'scim:read'),(1,'scim:write'),(1,'iam:admin.read'),(1,'iam:admin.write'),(2,'openid'),(2,'profile'),(2,'read-tasks'),(2,'write-tasks'),(3,'openid'),(3,'profile'),(3,'read-tasks'),(3,'write-tasks'),(4,'openid'),(4,'profile'),(4,'read-tasks'),(4,'write-tasks'),(4,'offline_access'),(4,'storage.read:/'),(4,'storage.write:/'),(4,'wlcg.groups'),(5,'openid'),(5,'profile'),(5,'email'),(5,'address'),(5,'phone'),(5,'offline_access'),(5,'scim:read'),(5,'scim:write'),(5,'proxy:generate'),(5,'wlcg'),(5,'wlcg.groups'),(5,'storage.read:/'),(5,'storage.modify:/'),(5,'storage.create:/'),(5,'attr'),(5,'aarc'),(5,'eduperson_scoped_affiliation'),(5,'eduperson_entitlement'),(5,'eduperson_assurance'),(5,'entitlements'),(5,'voperson_scoped_affiliation'),(6,'openid'),(6,'profile'),(6,'email'),(6,'address'),(6,'phone'),(6,'offline_access'),(6,'scim:read'),(7,'openid'),(7,'profile'),(7,'email'),(7,'address'),(7,'phone'),(7,'offline_access'),(7,'scim:read'),(7,'scim:write'),(7,'iam:admin.read'),(7,'iam:admin.write'),(8,'openid'),(8,'profile'),(8,'email'),(8,'address'),(8,'phone'),(8,'offline_access'),(8,'read-tasks'),(8,'storage.read:/'),(8,'storage.write:/'),(8,'wlcg.groups'),(9,'openid'),(9,'profile'),(9,'offline_access'),(9,'storage.read:/'),(9,'storage.write:/'),(10,'openid'),(10,'profile'),(10,'registration:read'),(10,'registration:write'),(10,'scim:write'),(10,'scim:read'),(11,'openid'),(11,'profile'),(11,'email'),(11,'address'),(11,'phone'),(11,'offline_access'),(11,'read-tasks'),(11,'write-tasks'),(12,'openid'),(12,'profile'),(12,'email'),(12,'address'),(12,'phone'),(12,'offline_access'),(12,'storage.read:/'),(12,'storage.write:/'),(12,'iam:admin.read'),(13,'openid'),(13,'profile'),(13,'email'),(13,'address'),(13,'phone'),(14,'profile'),(14,'email'),(14,'address'),(14,'phone'),(15,'openid'),(16,'openid'),(17,'iam:admin.read'),(18,'iam:admin.read'),(18,'iam:admin.write'),(19,'profile'),(19,'email'),(20,'openid'),(20,'profile'),(20,'email'),(20,'address'),(20,'phone'),(20,'offline_access'),(20,'storage.read:/'),(20,'storage.write:/'),(21,'openid'),(21,'profile'),(21,'email'),(21,'address'),(21,'phone'),(22,'openid'),(22,'profile'),(23,'openid'),(23,'profile'),(24,'openid'),(24,'profile'),(25,'openid'),(25,'profile'),(26,'openid'),(26,'profile'),(27,'openid'),(1,'storage.write:/'),(1,'storage.read:/'),(1,'storage.stage:/'),(1,'storage.create:/'),(1,'storage.modify:/');
/*!40000 ALTER TABLE `client_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `device_code`
--

DROP TABLE IF EXISTS `device_code`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_code` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `device_code` varchar(1024) DEFAULT NULL,
  `user_code` varchar(1024) DEFAULT NULL,
  `expiration` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `client_id` varchar(256) DEFAULT NULL,
  `approved` tinyint(1) DEFAULT NULL,
  `auth_holder_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `device_code`
--

LOCK TABLES `device_code` WRITE;
/*!40000 ALTER TABLE `device_code` DISABLE KEYS */;
/*!40000 ALTER TABLE `device_code` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `device_code_request_parameter`
--

DROP TABLE IF EXISTS `device_code_request_parameter`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_code_request_parameter` (
  `owner_id` bigint DEFAULT NULL,
  `param` varchar(2048) DEFAULT NULL,
  `val` varchar(2048) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `device_code_request_parameter`
--

LOCK TABLES `device_code_request_parameter` WRITE;
/*!40000 ALTER TABLE `device_code_request_parameter` DISABLE KEYS */;
/*!40000 ALTER TABLE `device_code_request_parameter` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `device_code_scope`
--

DROP TABLE IF EXISTS `device_code_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_code_scope` (
  `owner_id` bigint NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `device_code_scope`
--

LOCK TABLES `device_code_scope` WRITE;
/*!40000 ALTER TABLE `device_code_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `device_code_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account`
--

DROP TABLE IF EXISTS `iam_account`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `active` tinyint(1) NOT NULL DEFAULT '0',
  `CREATIONTIME` datetime NOT NULL,
  `LASTUPDATETIME` datetime NOT NULL,
  `PASSWORD` varchar(128) DEFAULT NULL,
  `USERNAME` varchar(128) NOT NULL,
  `UUID` varchar(36) NOT NULL,
  `user_info_id` bigint DEFAULT NULL,
  `confirmation_key` varchar(36) DEFAULT NULL,
  `reset_key` varchar(36) DEFAULT NULL,
  `provisioned` tinyint(1) NOT NULL DEFAULT '0',
  `last_login_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  `service_account` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `USERNAME` (`USERNAME`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_account_user_info_id` (`user_info_id`),
  KEY `ia_ct_idx` (`CREATIONTIME`),
  KEY `ia_lut_idx` (`LASTUPDATETIME`),
  KEY `ia_llt_idx` (`last_login_time`),
  KEY `ia_et_idx` (`end_time`),
  CONSTRAINT `FK_iam_account_user_info_id` FOREIGN KEY (`user_info_id`) REFERENCES `iam_user_info` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2001 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account`
--

LOCK TABLES `iam_account` WRITE;
/*!40000 ALTER TABLE `iam_account` DISABLE KEYS */;
INSERT INTO `iam_account` VALUES (1,1,'2026-11-23 14:40:43','2026-11-23 18:23:06','$2a$10$OOIb2zhDEoIdOcwOp9ZVd.kqQfPrqFjfjCbPrpXEwDZqVgDStrAv.','admin','73f16d93-2441-4a50-88ff-85360d78c6b5',1,NULL,NULL,0,'2026-11-23 18:23:06',NULL,0),(2,1,'2026-11-23 14:41:08','2026-11-23 15:01:28','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test','80e5fb8d-b7c8-451a-89ba-346ae278a66f',2,NULL,NULL,0,'2026-11-23 15:01:28',NULL,0),(3,1,'2026-11-23 14:40:43','2026-11-23 14:40:43','$2a$10$eWU1/dPT66exQIKfwEa/zu25kJNA6GhM8N7qqWUxGUmu2VI5rAviq','dup_email_0','bffc67b7-47fe-410c-a6a0-cf00173a8fbb',3,NULL,NULL,0,NULL,NULL,0),(4,1,'2026-11-23 14:40:43','2026-11-23 14:40:43','$2a$10$PkXUvVP2YCOGqN.Q6JLIx.NOdETV0VOrxtAyxPRPTOONvfI9hwzr6','dup_email_1','0a6fa72a-fb75-4a6c-9734-bfe673df70b3',4,NULL,NULL,0,NULL,NULL,0),(5,1,'2026-11-23 14:40:43','2026-11-23 14:40:43','$2a$10$N3o7zker.dIL4Zz7iYTQG.LEZEy7ixi47Phfqq1Plt6/G9CU9iB/a','dup_email_2','d836e5ec-246c-456c-8476-923ee2f831c8',5,NULL,NULL,0,NULL,NULL,0),(10,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','manager','8F9652DA-14D6-4674-A3B8-2AA091C841FD',10,NULL,NULL,0,NULL,NULL,0),(100,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_100','f2ce8cb2-a1db-4884-9ef0-d8842cc02b4a',100,NULL,NULL,0,NULL,NULL,0),(101,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_101','1a78b3b8-22d2-4746-9269-df55aceb036f',101,NULL,NULL,0,NULL,NULL,0),(102,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_102','a07d60c6-7ffa-475f-98e4-f9f648aa278b',102,NULL,NULL,0,NULL,NULL,0),(103,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_103','56e1b885-ea25-4ffc-ba17-fcde2b097d02',103,NULL,NULL,0,NULL,NULL,0),(104,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_104','67d2794d-c7fb-406e-9bc1-b66f43cbe60f',104,NULL,NULL,0,NULL,NULL,0),(105,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_105','d11e04f7-f369-4de6-9375-394f7d886ac7',105,NULL,NULL,0,NULL,NULL,0),(106,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_106','bbc76b76-9f9e-443b-8c63-cd775c50c6f3',106,NULL,NULL,0,NULL,NULL,0),(107,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_107','b15c850c-e6e0-4afb-a02d-374653bb102e',107,NULL,NULL,0,NULL,NULL,0),(108,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_108','afada6e8-d50d-47f6-912e-d6261605c771',108,NULL,NULL,0,NULL,NULL,0),(109,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_109','fa3b4c97-4787-4b49-a32c-5b4c74d5a7c8',109,NULL,NULL,0,NULL,NULL,0),(110,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_110','33165df6-4d49-4728-883c-3fd42720d46b',110,NULL,NULL,0,NULL,NULL,0),(111,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_111','15fb8d3a-003d-4ef9-8349-867d81d4ae9c',111,NULL,NULL,0,NULL,NULL,0),(112,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_112','7a4dda33-c2e5-4304-998a-3fa4df481123',112,NULL,NULL,0,NULL,NULL,0),(113,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_113','7013f989-0a95-43b5-8637-2e2360a73bb3',113,NULL,NULL,0,NULL,NULL,0),(114,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_114','12caabc8-4766-4028-98ff-f4d7f288a5f0',114,NULL,NULL,0,NULL,NULL,0),(115,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_115','f463ad2b-5814-4877-bb62-f954c67a8044',115,NULL,NULL,0,NULL,NULL,0),(116,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_116','28c656c4-5489-4654-a257-0806c6bab905',116,NULL,NULL,0,NULL,NULL,0),(117,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_117','11be5a72-9416-45fc-a0a7-f3e23c54bfda',117,NULL,NULL,0,NULL,NULL,0),(118,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_118','3cea2c01-786e-41a3-8fdf-4229cc4e3742',118,NULL,NULL,0,NULL,NULL,0),(119,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_119','e0247677-4542-4df3-8d75-8efa11e70911',119,NULL,NULL,0,NULL,NULL,0),(120,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_120','d905a115-d726-4e11-ba1f-b8482177bb05',120,NULL,NULL,0,NULL,NULL,0),(121,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_121','3479afd1-584c-4479-b6e2-25f6cef2f842',121,NULL,NULL,0,NULL,NULL,0),(122,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_122','8d4f467d-cb68-4feb-b898-71e4487e6820',122,NULL,NULL,0,NULL,NULL,0),(123,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_123','0ddee1c2-1426-4b83-b520-e20bdd8ef9b3',123,NULL,NULL,0,NULL,NULL,0),(124,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_124','b8b638be-6e09-4dbe-bcc0-776c2403e8c7',124,NULL,NULL,0,NULL,NULL,0),(125,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_125','1dc3108a-b5c0-4e5b-accd-925054075bc4',125,NULL,NULL,0,NULL,NULL,0),(126,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_126','5eed3374-c131-4513-84b7-dd0ff965da35',126,NULL,NULL,0,NULL,NULL,0),(127,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_127','2d0b4c36-0301-49f6-a20b-23b6ca48cee2',127,NULL,NULL,0,NULL,NULL,0),(128,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_128','db46065a-ba62-423d-9397-7bc6fab371a5',128,NULL,NULL,0,NULL,NULL,0),(129,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_129','d9dbaabf-c51a-45e5-aee1-25134ba283ac',129,NULL,NULL,0,NULL,NULL,0),(130,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_130','5678f40a-f361-464c-aa71-ffb48d163aaa',130,NULL,NULL,0,NULL,NULL,0),(131,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_131','209ae3b9-e266-4e57-a639-db29f61a7594',131,NULL,NULL,0,NULL,NULL,0),(132,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_132','f3fac505-d5c9-4d9c-83af-3976f357f19c',132,NULL,NULL,0,NULL,NULL,0),(133,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_133','13bfd34b-1dda-452e-bd9a-284aabccf07d',133,NULL,NULL,0,NULL,NULL,0),(134,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_134','15ccd152-1537-48d4-a55a-fd6565e5d86f',134,NULL,NULL,0,NULL,NULL,0),(135,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_135','6b2f4fc1-3e98-4f64-8fb4-517d2d4b3fa3',135,NULL,NULL,0,NULL,NULL,0),(136,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_136','398081ee-9c3c-4e5d-802c-90a4579030d4',136,NULL,NULL,0,NULL,NULL,0),(137,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_137','89a32317-dd45-481d-91a4-080e30c1f29e',137,NULL,NULL,0,NULL,NULL,0),(138,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_138','6dc0aa56-011d-45b8-bf26-cb03e8b40ccf',138,NULL,NULL,0,NULL,NULL,0),(139,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_139','cd62277e-5acf-41af-acea-b4d208cba29e',139,NULL,NULL,0,NULL,NULL,0),(140,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_140','0ae29eac-64ee-45b4-a2e7-e58b34c7ff0e',140,NULL,NULL,0,NULL,NULL,0),(141,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_141','0f7fe907-fa84-429e-8057-02d809375ba3',141,NULL,NULL,0,NULL,NULL,0),(142,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_142','7aa4a733-d318-4392-b3d3-6618263f667d',142,NULL,NULL,0,NULL,NULL,0),(143,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_143','b1d9b1ac-e77c-4d55-a895-cf0788ed2174',143,NULL,NULL,0,NULL,NULL,0),(144,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_144','f975f1f7-ad05-4d66-9905-d44c13cbd08b',144,NULL,NULL,0,NULL,NULL,0),(145,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_145','857f6e6d-e415-4850-a82b-59d557864910',145,NULL,NULL,0,NULL,NULL,0),(146,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_146','4e1c059c-1d06-4997-8bfa-5bd09fdb4571',146,NULL,NULL,0,NULL,NULL,0),(147,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_147','f4a0bc7f-b279-4caf-b8d1-c86a3c106f62',147,NULL,NULL,0,NULL,NULL,0),(148,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_148','007bbb9d-55b1-4f5e-80a5-bbcb22073db4',148,NULL,NULL,0,NULL,NULL,0),(149,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_149','a1d22bbf-9afe-49da-b75d-b58f825db351',149,NULL,NULL,0,NULL,NULL,0),(150,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_150','8c2351d5-5460-4b2d-b1bb-7b086130090e',150,NULL,NULL,0,NULL,NULL,0),(151,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_151','e6651896-66f8-4f63-b44f-71710fdb947c',151,NULL,NULL,0,NULL,NULL,0),(152,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_152','caf04a3c-8f35-40a3-99b6-48ba6a05d8b8',152,NULL,NULL,0,NULL,NULL,0),(153,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_153','d501e485-a306-4c9d-9baf-cc75f2321cfd',153,NULL,NULL,0,NULL,NULL,0),(154,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_154','57466d38-cae8-48bf-ac67-2cfc0266b5b0',154,NULL,NULL,0,NULL,NULL,0),(155,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_155','4bd5f059-f014-4356-8083-9c1a77adb6fd',155,NULL,NULL,0,NULL,NULL,0),(156,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_156','69130f52-f251-46fd-99ee-d646938e5f3f',156,NULL,NULL,0,NULL,NULL,0),(157,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_157','dedfb4f0-a545-44b3-abba-dd77103db894',157,NULL,NULL,0,NULL,NULL,0),(158,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_158','b5d98a8b-3780-4ace-ace1-ac12829dc469',158,NULL,NULL,0,NULL,NULL,0),(159,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_159','17de2f08-37fe-469d-b7b1-0e9ea9c6d2d8',159,NULL,NULL,0,NULL,NULL,0),(160,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_160','313abc40-4c88-45df-89e7-bd7bbf97b0fd',160,NULL,NULL,0,NULL,NULL,0),(161,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_161','c5d7fc06-16fc-4711-be37-27bbf2c2c07c',161,NULL,NULL,0,NULL,NULL,0),(162,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_162','ca31bf4d-f5da-4fc4-ae36-fd3cc0d35d7f',162,NULL,NULL,0,NULL,NULL,0),(163,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_163','dc98bb8e-4b91-4915-86fb-476c9503a936',163,NULL,NULL,0,NULL,NULL,0),(164,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_164','79dd006c-0e4c-4a79-8600-ef8a0ae5bc04',164,NULL,NULL,0,NULL,NULL,0),(165,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_165','05cdc1f7-7787-43d6-80c6-588277fefb9b',165,NULL,NULL,0,NULL,NULL,0),(166,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_166','dcdeb139-71ab-44f5-a709-ab33fec49882',166,NULL,NULL,0,NULL,NULL,0),(167,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_167','35a98804-b05e-47b0-917b-d72a4d4a5240',167,NULL,NULL,0,NULL,NULL,0),(168,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_168','5e4d4351-82c7-438d-8f83-ee2b7ebe1fe3',168,NULL,NULL,0,NULL,NULL,0),(169,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_169','e1a205e2-f202-402d-8542-4cfc529ef514',169,NULL,NULL,0,NULL,NULL,0),(170,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_170','a2e6271e-5b30-42d1-a211-494b98832676',170,NULL,NULL,0,NULL,NULL,0),(171,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_171','68515954-75ea-4022-9581-4cb4d28c6d6d',171,NULL,NULL,0,NULL,NULL,0),(172,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_172','41663b84-06b5-4787-a49e-1f745ca1eab3',172,NULL,NULL,0,NULL,NULL,0),(173,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_173','b257f456-bdae-4c58-8519-756abbda462a',173,NULL,NULL,0,NULL,NULL,0),(174,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_174','d848b9cb-05e4-4dcf-b9b7-431d83c41810',174,NULL,NULL,0,NULL,NULL,0),(175,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_175','b6859250-dcca-47ef-b013-f609468d2389',175,NULL,NULL,0,NULL,NULL,0),(176,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_176','e18bc682-897b-4696-a5ef-eee37a52a3de',176,NULL,NULL,0,NULL,NULL,0),(177,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_177','6b00471d-f496-4335-8209-5a9e13d18b9e',177,NULL,NULL,0,NULL,NULL,0),(178,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_178','35664644-7b32-4503-86f4-76adbb57762c',178,NULL,NULL,0,NULL,NULL,0),(179,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_179','7890415f-6563-4f25-bdf3-a5f45159a1b1',179,NULL,NULL,0,NULL,NULL,0),(180,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_180','a1edf880-e270-4dac-b69f-73e61c517397',180,NULL,NULL,0,NULL,NULL,0),(181,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_181','73520029-5901-4022-b9da-38ccd73fe799',181,NULL,NULL,0,NULL,NULL,0),(182,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_182','de5825a3-c585-45b3-88a1-7e5e80686826',182,NULL,NULL,0,NULL,NULL,0),(183,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_183','bb50b80a-f471-4f64-85fb-4e5051708a4a',183,NULL,NULL,0,NULL,NULL,0),(184,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_184','b7aa98b9-30da-468c-8566-06a5b804c4b9',184,NULL,NULL,0,NULL,NULL,0),(185,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_185','c230e253-f874-4365-8b0e-7ba5ebc1cc26',185,NULL,NULL,0,NULL,NULL,0),(186,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_186','7593dbbf-9286-460b-a234-32b560817f60',186,NULL,NULL,0,NULL,NULL,0),(187,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_187','ee1e2ce5-da23-4576-84e3-ad7cf4e0ce26',187,NULL,NULL,0,NULL,NULL,0),(188,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_188','bf1cc1be-f405-4282-b7be-9a4578670046',188,NULL,NULL,0,NULL,NULL,0),(189,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_189','e5ed670a-f944-40f0-8c10-d41c3350ead5',189,NULL,NULL,0,NULL,NULL,0),(190,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_190','8370db5c-e196-451a-9f5f-9b99c570cf46',190,NULL,NULL,0,NULL,NULL,0),(191,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_191','81498342-d247-4a60-80de-2c4cb4b1a84d',191,NULL,NULL,0,NULL,NULL,0),(192,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_192','213f1b3c-516e-4a6f-9785-d8c85d32f83e',192,NULL,NULL,0,NULL,NULL,0),(193,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_193','08ba27e6-b1b5-4d9e-a64a-6b5bc538bf43',193,NULL,NULL,0,NULL,NULL,0),(194,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_194','cf0cfa8e-377c-44a0-a6d1-a74ce1de08fb',194,NULL,NULL,0,NULL,NULL,0),(195,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_195','2ea66412-8dc2-4081-8d48-e3637ca82604',195,NULL,NULL,0,NULL,NULL,0),(196,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_196','4ed466eb-ee51-4433-9d0f-3a56216698a2',196,NULL,NULL,0,NULL,NULL,0),(197,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_197','cc03fc51-097d-43d6-bb6c-a0df72ec4838',197,NULL,NULL,0,NULL,NULL,0),(198,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_198','11844e66-8146-4263-aaa6-1fde7e5cfc58',198,NULL,NULL,0,NULL,NULL,0),(199,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_199','b5a954c6-69a9-473c-a4c4-83c4f7a88c1c',199,NULL,NULL,0,NULL,NULL,0),(200,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_200','167e359e-7833-4ce2-9f8b-f035cee39505',200,NULL,NULL,0,NULL,NULL,0),(201,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_201','5afb5430-a023-4a50-aa92-b134a0fb68b3',201,NULL,NULL,0,NULL,NULL,0),(202,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_202','de17b155-307c-4f9b-81f3-7f8b73d2526a',202,NULL,NULL,0,NULL,NULL,0),(203,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_203','c966145b-ac05-4a2c-874d-f7b585d1d03b',203,NULL,NULL,0,NULL,NULL,0),(204,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_204','1d88ea5a-ab5f-40b1-bd48-f18f86eef5d9',204,NULL,NULL,0,NULL,NULL,0),(205,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_205','6cb0be93-7829-4bfc-ba4a-4d2cdff45447',205,NULL,NULL,0,NULL,NULL,0),(206,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_206','e31a2ca7-fcaa-4b98-aac9-7e78f8605851',206,NULL,NULL,0,NULL,NULL,0),(207,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_207','f26899b7-64e0-4c16-9134-cef3774f1614',207,NULL,NULL,0,NULL,NULL,0),(208,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_208','606cf6ab-6b5e-45d1-83b8-e535b197d2f0',208,NULL,NULL,0,NULL,NULL,0),(209,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_209','617bfc4e-17b1-4ca7-b736-58a74c267747',209,NULL,NULL,0,NULL,NULL,0),(210,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_210','e5c26b7a-17bd-47ce-aac8-1430c57b8152',210,NULL,NULL,0,NULL,NULL,0),(211,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_211','7747bff5-b1e5-49b9-9a87-f93a5b790df0',211,NULL,NULL,0,NULL,NULL,0),(212,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_212','c6e5b631-1e91-4ecd-8358-214eec07a91d',212,NULL,NULL,0,NULL,NULL,0),(213,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_213','a874c7bd-97ac-4f48-bda5-7d3305d9067d',213,NULL,NULL,0,NULL,NULL,0),(214,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_214','c7938cc2-8032-424b-8f49-85558f95364b',214,NULL,NULL,0,NULL,NULL,0),(215,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_215','46017ce9-d4dd-4ddc-8b73-d596e23d25ad',215,NULL,NULL,0,NULL,NULL,0),(216,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_216','d5e66fd2-232e-476d-8de0-2bc1eb59630d',216,NULL,NULL,0,NULL,NULL,0),(217,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_217','097dc614-bc56-4f5f-a190-3ca1716a6400',217,NULL,NULL,0,NULL,NULL,0),(218,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_218','a3b97132-067f-4839-9b99-830a7fb659d4',218,NULL,NULL,0,NULL,NULL,0),(219,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_219','8d35557f-7451-4c54-bb17-9c3d204c48d3',219,NULL,NULL,0,NULL,NULL,0),(220,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_220','a6fba1ff-a5d7-4907-8cd4-1caa27cad85d',220,NULL,NULL,0,NULL,NULL,0),(221,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_221','427feb36-4401-4971-83de-f93672c028aa',221,NULL,NULL,0,NULL,NULL,0),(222,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_222','66541083-b1ab-4966-9f8b-8a1109fce0e0',222,NULL,NULL,0,NULL,NULL,0),(223,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_223','9939c37c-a9b9-43b7-9a4b-aacc470d47c4',223,NULL,NULL,0,NULL,NULL,0),(224,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_224','754379a0-bdc2-4a2d-9828-9480926b30ad',224,NULL,NULL,0,NULL,NULL,0),(225,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_225','18c870a1-9e2c-48fb-8a52-259e55e2052e',225,NULL,NULL,0,NULL,NULL,0),(226,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_226','02df9a97-b44c-4c46-ab3a-c11010d45e18',226,NULL,NULL,0,NULL,NULL,0),(227,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_227','20f609f7-c128-46b5-abeb-d16d46aab9ad',227,NULL,NULL,0,NULL,NULL,0),(228,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_228','75067ca5-872c-4149-85ad-f6685f14efc0',228,NULL,NULL,0,NULL,NULL,0),(229,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_229','b8639303-d15f-4c81-b9d2-2863f53737c3',229,NULL,NULL,0,NULL,NULL,0),(230,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_230','a0c4d9ea-7659-4009-ac7c-a3f089def76d',230,NULL,NULL,0,NULL,NULL,0),(231,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_231','d3605113-fb9a-4640-b6fe-9931594eba6c',231,NULL,NULL,0,NULL,NULL,0),(232,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_232','bf59d2cc-dd79-4ad6-9637-b04098768600',232,NULL,NULL,0,NULL,NULL,0),(233,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_233','304d5f24-274e-4fd6-aca4-97b761d1bd0c',233,NULL,NULL,0,NULL,NULL,0),(234,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_234','0d9491c3-c28b-4c11-8e28-14d93e612e35',234,NULL,NULL,0,NULL,NULL,0),(235,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_235','f73a809f-78a6-4214-8060-d6037fe391aa',235,NULL,NULL,0,NULL,NULL,0),(236,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_236','11cc494a-86a4-44d2-b5fd-06438f95d6a4',236,NULL,NULL,0,NULL,NULL,0),(237,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_237','55b2e8cc-aaa4-4a8b-8a83-f732188cfab2',237,NULL,NULL,0,NULL,NULL,0),(238,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_238','ebe14f0a-7bf7-4614-83c8-1e2da963139a',238,NULL,NULL,0,NULL,NULL,0),(239,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_239','3e83b092-95a1-4ee4-ac1f-e9df2f3954ad',239,NULL,NULL,0,NULL,NULL,0),(240,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_240','7304efcc-7974-453e-b2db-fdcc848f8a24',240,NULL,NULL,0,NULL,NULL,0),(241,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_241','6b0b51e8-f058-42a6-a9ed-3b6ebde935d8',241,NULL,NULL,0,NULL,NULL,0),(242,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_242','c10f6de1-a64d-4f8f-bd0a-47bcd72ab8f7',242,NULL,NULL,0,NULL,NULL,0),(243,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_243','5537408c-41c6-4ee5-8f59-ca70fcdbd0ae',243,NULL,NULL,0,NULL,NULL,0),(244,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_244','0a920520-e271-42a6-8dc1-89f090023c89',244,NULL,NULL,0,NULL,NULL,0),(245,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_245','a5120b27-cdd5-4209-b3da-bdf4b53db140',245,NULL,NULL,0,NULL,NULL,0),(246,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_246','cd0f900a-dab8-4a49-805d-97e57cb5ad4c',246,NULL,NULL,0,NULL,NULL,0),(247,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_247','53b8b68c-0a11-411a-9b4d-01d58c9c0ff0',247,NULL,NULL,0,NULL,NULL,0),(248,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_248','57114ddf-7bb8-4e68-952a-faa83bf276bf',248,NULL,NULL,0,NULL,NULL,0),(249,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_249','fa04c6fe-1bf0-489e-b0df-9fa4756bb90b',249,NULL,NULL,0,NULL,NULL,0),(250,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_250','5bf5b365-962e-4f6d-9576-94d5ac66cc3c',250,NULL,NULL,0,NULL,NULL,0),(251,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_251','eca96575-798c-4919-ba93-4f0eca487490',251,NULL,NULL,0,NULL,NULL,0),(252,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_252','d4e52ad1-ac1c-4f68-8d97-6858c8534f84',252,NULL,NULL,0,NULL,NULL,0),(253,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_253','74f88528-b57b-4482-a417-e7e8cf5ccd87',253,NULL,NULL,0,NULL,NULL,0),(254,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_254','f1b969bd-2e43-4981-80d1-baeba6afd456',254,NULL,NULL,0,NULL,NULL,0),(255,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_255','11f5bcd3-096b-4b0f-8f1b-fa9292e3f5f3',255,NULL,NULL,0,NULL,NULL,0),(256,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_256','b937e637-c00b-48de-8dd4-fae260cd9fb9',256,NULL,NULL,0,NULL,NULL,0),(257,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_257','49886ca5-c9a8-4c1f-9ef0-4784495e943c',257,NULL,NULL,0,NULL,NULL,0),(258,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_258','5cf6bbba-f2bf-4704-b288-36edb49a3c7a',258,NULL,NULL,0,NULL,NULL,0),(259,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_259','0a246675-78f2-47d3-a716-f9b85de0e885',259,NULL,NULL,0,NULL,NULL,0),(260,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_260','b1e2509b-e9e4-40f8-b5c3-4e230e675ca8',260,NULL,NULL,0,NULL,NULL,0),(261,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_261','c423ca4a-54b4-40f3-859d-d39f7d4cf266',261,NULL,NULL,0,NULL,NULL,0),(262,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_262','1452d005-8038-4092-ba0d-bd690dfdb2e2',262,NULL,NULL,0,NULL,NULL,0),(263,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_263','f39a1721-6aeb-4f1e-90be-f54684ece8f0',263,NULL,NULL,0,NULL,NULL,0),(264,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_264','ec2b02db-6eb2-4b9e-aa3b-ef53b6daf005',264,NULL,NULL,0,NULL,NULL,0),(265,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_265','a6809581-e7b7-4d70-bfdd-c1f302322ee3',265,NULL,NULL,0,NULL,NULL,0),(266,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_266','794e2ba9-518d-4494-8ef0-01669807e10a',266,NULL,NULL,0,NULL,NULL,0),(267,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_267','c258f48e-7f30-4c16-bd2d-6eed81529157',267,NULL,NULL,0,NULL,NULL,0),(268,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_268','b7501b84-3a14-44d7-97da-271c416cbd16',268,NULL,NULL,0,NULL,NULL,0),(269,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_269','88b529d5-7804-4c4d-9f35-aa7dd1df0a37',269,NULL,NULL,0,NULL,NULL,0),(270,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_270','0c1b65d3-dee3-4429-864f-115fbbc6a2f4',270,NULL,NULL,0,NULL,NULL,0),(271,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_271','01667b0f-b397-47c1-8cdb-adb3ea7cba06',271,NULL,NULL,0,NULL,NULL,0),(272,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_272','c8909fda-0453-4f74-a683-bd613fdc70c5',272,NULL,NULL,0,NULL,NULL,0),(273,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_273','796b8703-6f42-433f-b9e6-b115b4df25b0',273,NULL,NULL,0,NULL,NULL,0),(274,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_274','de8f11f6-7298-4633-ad38-cc94e03314fd',274,NULL,NULL,0,NULL,NULL,0),(275,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_275','e097f4e6-9c2d-4f35-912e-bd37f5cdec00',275,NULL,NULL,0,NULL,NULL,0),(276,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_276','3e0dab1e-c41f-4c0d-b2e3-d056ba6a3c60',276,NULL,NULL,0,NULL,NULL,0),(277,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_277','b24cb998-40b7-471c-b55a-48b58b98b2e5',277,NULL,NULL,0,NULL,NULL,0),(278,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_278','ab2113f4-56a2-4d1d-83a6-a54a763e371e',278,NULL,NULL,0,NULL,NULL,0),(279,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_279','2a2beb83-ccbf-413f-ade2-2fd2f79e5f49',279,NULL,NULL,0,NULL,NULL,0),(280,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_280','ac53405d-8813-4cf7-ac12-fad7629d5602',280,NULL,NULL,0,NULL,NULL,0),(281,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_281','b6c7b0e1-38b5-4e00-a22d-45c03d5fdeac',281,NULL,NULL,0,NULL,NULL,0),(282,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_282','8e41ff90-42f5-4736-89a6-24246917555c',282,NULL,NULL,0,NULL,NULL,0),(283,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_283','2b46023a-316f-41ae-955e-01185d67d7a5',283,NULL,NULL,0,NULL,NULL,0),(284,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_284','74c72c06-391e-4c72-92e7-92a5b75ac2da',284,NULL,NULL,0,NULL,NULL,0),(285,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_285','3e1246c2-96f9-4937-be0c-eb187822c3c7',285,NULL,NULL,0,NULL,NULL,0),(286,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_286','7f0e0193-b743-4394-b3e5-86e01813c094',286,NULL,NULL,0,NULL,NULL,0),(287,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_287','886cd06c-c30a-48df-b793-be4bfa2c1eb9',287,NULL,NULL,0,NULL,NULL,0),(288,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_288','cb7cf6cd-bd2e-4956-be86-5d5935417098',288,NULL,NULL,0,NULL,NULL,0),(289,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_289','d2e92f17-c26b-44dd-9c60-ca69b0f55b6d',289,NULL,NULL,0,NULL,NULL,0),(290,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_290','ea3a53a1-b451-4d7b-9b9f-2b6790de314d',290,NULL,NULL,0,NULL,NULL,0),(291,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_291','723f2b0d-3473-445c-a6f2-9c8bb12b6019',291,NULL,NULL,0,NULL,NULL,0),(292,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_292','8f04e723-bb30-4952-a8f5-214845e525dc',292,NULL,NULL,0,NULL,NULL,0),(293,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_293','56e1991e-47e1-4136-9bd0-cd94fa40b3c8',293,NULL,NULL,0,NULL,NULL,0),(294,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_294','b5ef5b82-483e-4331-ba84-78ece1f72602',294,NULL,NULL,0,NULL,NULL,0),(295,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_295','8238ae4e-5f13-42a3-9d6c-ea60f0ee64a1',295,NULL,NULL,0,NULL,NULL,0),(296,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_296','800a6a1d-1f63-4052-a14a-fcb56ab7e98b',296,NULL,NULL,0,NULL,NULL,0),(297,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_297','2eb884c0-8953-434d-898f-a162ffd44102',297,NULL,NULL,0,NULL,NULL,0),(298,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_298','06363941-bac6-4cc1-b56f-82d9d64d7c12',298,NULL,NULL,0,NULL,NULL,0),(299,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_299','d8468131-79a2-4003-bf0a-e034a3455af9',299,NULL,NULL,0,NULL,NULL,0),(300,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_300','e8e5f9d3-4473-46d9-b893-a195d5ccc6b4',300,NULL,NULL,0,NULL,NULL,0),(301,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_301','57db1144-49b7-4930-a214-9bba56c0eab6',301,NULL,NULL,0,NULL,NULL,0),(302,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_302','668a6ec5-142f-467d-891a-57fe10faf4bb',302,NULL,NULL,0,NULL,NULL,0),(303,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_303','9bcd9772-6c90-4c14-8ff4-16fa54744c87',303,NULL,NULL,0,NULL,NULL,0),(304,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_304','6c37ac4e-5213-4d60-8070-fadf3fa3ca38',304,NULL,NULL,0,NULL,NULL,0),(305,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_305','fb5d7ea0-249f-4a0e-97aa-caa015d148e4',305,NULL,NULL,0,NULL,NULL,0),(306,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_306','26035205-595c-433a-8aba-4e0d6ce103a3',306,NULL,NULL,0,NULL,NULL,0),(307,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_307','1e4a6346-9da9-417c-bfbf-1a3cded61e12',307,NULL,NULL,0,NULL,NULL,0),(308,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_308','3af98cba-0cd4-4ea1-bcdc-c4c91672f038',308,NULL,NULL,0,NULL,NULL,0),(309,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_309','a073f7ce-dfdc-424c-b4d0-bec7acaae445',309,NULL,NULL,0,NULL,NULL,0),(310,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_310','6524988e-5916-4410-a740-58d1e57d3f93',310,NULL,NULL,0,NULL,NULL,0),(311,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_311','58a190c4-789e-4c97-9fbb-245d3a58c8fe',311,NULL,NULL,0,NULL,NULL,0),(312,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_312','3244773f-b74b-461d-bf9a-916a05980c99',312,NULL,NULL,0,NULL,NULL,0),(313,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_313','aaed5fa8-6555-43d2-adf4-c672008f8c92',313,NULL,NULL,0,NULL,NULL,0),(314,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_314','f32415ac-f0fb-4815-bbef-27ba6115a1cc',314,NULL,NULL,0,NULL,NULL,0),(315,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_315','2030b697-b729-40c4-91b1-592e19fd4e73',315,NULL,NULL,0,NULL,NULL,0),(316,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_316','ee47b98e-ebd5-44ae-8c9a-cbec609415b0',316,NULL,NULL,0,NULL,NULL,0),(317,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_317','a47459c2-a709-4601-9151-cb57ae13bc8c',317,NULL,NULL,0,NULL,NULL,0),(318,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_318','5e274495-2c02-4f75-9ce2-c730e2686be9',318,NULL,NULL,0,NULL,NULL,0),(319,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_319','f5f04ca8-f693-4758-9aa6-9a3c55938937',319,NULL,NULL,0,NULL,NULL,0),(320,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_320','5f876faf-2ad7-41f3-906d-2edd9fd2907d',320,NULL,NULL,0,NULL,NULL,0),(321,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_321','3d0665c6-db74-4d48-91cc-ebe39bbae605',321,NULL,NULL,0,NULL,NULL,0),(322,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_322','86c19bce-cb25-47a4-8aba-29c8ad4fc87d',322,NULL,NULL,0,NULL,NULL,0),(323,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_323','efa06619-2301-4cb4-b9fa-6e9bddef94d7',323,NULL,NULL,0,NULL,NULL,0),(324,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_324','3cfc5976-aa7f-4281-8b43-6ea6eee1ac80',324,NULL,NULL,0,NULL,NULL,0),(325,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_325','19a56d56-1f57-45e6-9c2e-466a17d8c7ba',325,NULL,NULL,0,NULL,NULL,0),(326,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_326','026a45cf-cbeb-4ea9-8d20-21efbe206bad',326,NULL,NULL,0,NULL,NULL,0),(327,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_327','48312cae-f61d-4f87-9b20-a957d1e919ce',327,NULL,NULL,0,NULL,NULL,0),(328,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_328','e06abc58-f451-4e9e-ac4f-51d5e9d424a6',328,NULL,NULL,0,NULL,NULL,0),(329,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_329','10b58273-4b30-4caf-954c-a1873ca4d6b5',329,NULL,NULL,0,NULL,NULL,0),(330,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_330','008892b7-6479-4e68-adf2-39e7ac29e66e',330,NULL,NULL,0,NULL,NULL,0),(331,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_331','7f864422-153c-4681-8c9e-4e942dce9548',331,NULL,NULL,0,NULL,NULL,0),(332,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_332','67c5538e-0363-4650-a42e-ba25746b4239',332,NULL,NULL,0,NULL,NULL,0),(333,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_333','208210c1-1601-47ae-883f-cdb16e0f802b',333,NULL,NULL,0,NULL,NULL,0),(334,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_334','bb08395a-a0f0-490d-9d23-6f2f76b41514',334,NULL,NULL,0,NULL,NULL,0),(335,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_335','050c1a8e-256d-41ab-bd3a-3abe54d01b32',335,NULL,NULL,0,NULL,NULL,0),(336,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_336','cf016005-9207-4a2d-a8fe-91c278029a18',336,NULL,NULL,0,NULL,NULL,0),(337,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_337','950a5d40-e604-4f6c-82dd-2b60a578d9aa',337,NULL,NULL,0,NULL,NULL,0),(338,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_338','3e00662d-6917-4759-b9a9-be8eda02f63b',338,NULL,NULL,0,NULL,NULL,0),(339,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_339','bb339af3-2038-4f17-b489-46d4b7542cb6',339,NULL,NULL,0,NULL,NULL,0),(340,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_340','3927f6d5-5d90-4192-b84c-cebda90c0b0a',340,NULL,NULL,0,NULL,NULL,0),(341,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_341','e6b29f71-bb4a-420b-8442-1f7639109465',341,NULL,NULL,0,NULL,NULL,0),(342,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_342','ff7909b6-a90c-43c7-96fc-c375d439e373',342,NULL,NULL,0,NULL,NULL,0),(343,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_343','6f9902ca-7674-4f2f-b2e1-aeb3701bae14',343,NULL,NULL,0,NULL,NULL,0),(344,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_344','36d75eda-7573-474a-8aeb-f8555464154f',344,NULL,NULL,0,NULL,NULL,0),(345,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_345','d3c489ae-3f03-48fe-9248-927a8bb3297f',345,NULL,NULL,0,NULL,NULL,0),(346,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_346','18764a4e-8b01-478e-80b3-217cc37d49c7',346,NULL,NULL,0,NULL,NULL,0),(347,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_347','00075d1c-f486-41a0-98f8-06f0354b8416',347,NULL,NULL,0,NULL,NULL,0),(1000,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$12$S3lUZw/ESq9lULn5he6bBu9KNGCvs7C2rWo0XdVC6t65ITwAc22w2','test-with-mfa','467c882e-90da-11ec-b909-0242ac120002',1000,NULL,NULL,0,NULL,NULL,0),(2000,1,'2026-11-23 14:41:08','2026-11-23 14:41:08','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','unverified-user','37d205e3-df24-4171-a9a4-07b427055782',2000,NULL,NULL,0,NULL,NULL,0);
/*!40000 ALTER TABLE `iam_account` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_attrs`
--

DROP TABLE IF EXISTS `iam_account_attrs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_attrs` (
  `NAME` varchar(64) NOT NULL,
  `val` varchar(256) DEFAULT NULL,
  `account_id` bigint DEFAULT NULL,
  KEY `INDEX_iam_account_attrs_name` (`NAME`),
  KEY `INDEX_iam_account_attrs_name_val` (`NAME`,`val`),
  KEY `FK_iam_account_attrs_account_id` (`account_id`),
  CONSTRAINT `FK_iam_account_attrs_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_attrs`
--

LOCK TABLES `iam_account_attrs` WRITE;
/*!40000 ALTER TABLE `iam_account_attrs` DISABLE KEYS */;
INSERT INTO `iam_account_attrs` VALUES ('affiliation','INFN-CNAF',10);
/*!40000 ALTER TABLE `iam_account_attrs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_authority`
--

DROP TABLE IF EXISTS `iam_account_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_authority` (
  `account_id` bigint NOT NULL,
  `authority_id` bigint NOT NULL,
  PRIMARY KEY (`account_id`,`authority_id`),
  KEY `FK_iam_account_authority_authority_id` (`authority_id`),
  CONSTRAINT `FK_iam_account_authority_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_account_authority_authority_id` FOREIGN KEY (`authority_id`) REFERENCES `iam_authority` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_authority`
--

LOCK TABLES `iam_account_authority` WRITE;
/*!40000 ALTER TABLE `iam_account_authority` DISABLE KEYS */;
INSERT INTO `iam_account_authority` VALUES (1,1),(1,2),(2,2),(10,2),(100,2),(101,2),(102,2),(103,2),(104,2),(105,2),(106,2),(107,2),(108,2),(109,2),(110,2),(111,2),(112,2),(113,2),(114,2),(115,2),(116,2),(117,2),(118,2),(119,2),(120,2),(121,2),(122,2),(123,2),(124,2),(125,2),(126,2),(127,2),(128,2),(129,2),(130,2),(131,2),(132,2),(133,2),(134,2),(135,2),(136,2),(137,2),(138,2),(139,2),(140,2),(141,2),(142,2),(143,2),(144,2),(145,2),(146,2),(147,2),(148,2),(149,2),(150,2),(151,2),(152,2),(153,2),(154,2),(155,2),(156,2),(157,2),(158,2),(159,2),(160,2),(161,2),(162,2),(163,2),(164,2),(165,2),(166,2),(167,2),(168,2),(169,2),(170,2),(171,2),(172,2),(173,2),(174,2),(175,2),(176,2),(177,2),(178,2),(179,2),(180,2),(181,2),(182,2),(183,2),(184,2),(185,2),(186,2),(187,2),(188,2),(189,2),(190,2),(191,2),(192,2),(193,2),(194,2),(195,2),(196,2),(197,2),(198,2),(199,2),(200,2),(201,2),(202,2),(203,2),(204,2),(205,2),(206,2),(207,2),(208,2),(209,2),(210,2),(211,2),(212,2),(213,2),(214,2),(215,2),(216,2),(217,2),(218,2),(219,2),(220,2),(221,2),(222,2),(223,2),(224,2),(225,2),(226,2),(227,2),(228,2),(229,2),(230,2),(231,2),(232,2),(233,2),(234,2),(235,2),(236,2),(237,2),(238,2),(239,2),(240,2),(241,2),(242,2),(243,2),(244,2),(245,2),(246,2),(247,2),(248,2),(249,2),(250,2),(251,2),(252,2),(253,2),(254,2),(255,2),(256,2),(257,2),(258,2),(259,2),(260,2),(261,2),(262,2),(263,2),(264,2),(265,2),(266,2),(267,2),(268,2),(269,2),(270,2),(271,2),(272,2),(273,2),(274,2),(275,2),(276,2),(277,2),(278,2),(279,2),(280,2),(281,2),(282,2),(283,2),(284,2),(285,2),(286,2),(287,2),(288,2),(289,2),(290,2),(291,2),(292,2),(293,2),(294,2),(295,2),(296,2),(297,2),(298,2),(299,2),(300,2),(301,2),(302,2),(303,2),(304,2),(305,2),(306,2),(307,2),(308,2),(309,2),(310,2),(311,2),(312,2),(313,2),(314,2),(315,2),(316,2),(317,2),(318,2),(319,2),(320,2),(321,2),(322,2),(323,2),(324,2),(325,2),(326,2),(327,2),(328,2),(329,2),(330,2),(331,2),(332,2),(333,2),(334,2),(335,2),(336,2),(337,2),(338,2),(339,2),(340,2),(341,2),(342,2),(343,2),(344,2),(345,2),(346,2),(347,2),(1000,2),(10,5);
/*!40000 ALTER TABLE `iam_account_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_client`
--

DROP TABLE IF EXISTS `iam_account_client`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_client` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `account_id` bigint NOT NULL,
  `client_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UNQ_iam_account_client_0` (`account_id`,`client_id`),
  KEY `FK_iam_account_client_client_id` (`client_id`),
  CONSTRAINT `FK_iam_account_client_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_account_client_client_id` FOREIGN KEY (`client_id`) REFERENCES `client_details` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_client`
--

LOCK TABLES `iam_account_client` WRITE;
/*!40000 ALTER TABLE `iam_account_client` DISABLE KEYS */;
INSERT INTO `iam_account_client` VALUES (1,'2026-11-23 14:41:08',200,1),(2,'2026-11-23 14:41:08',200,2),(3,'2026-11-23 14:41:08',199,1),(4,'2026-11-23 14:41:08',199,2);
/*!40000 ALTER TABLE `iam_account_client` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_group`
--

DROP TABLE IF EXISTS `iam_account_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_group` (
  `account_id` bigint NOT NULL,
  `group_id` bigint NOT NULL,
  `creation_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  PRIMARY KEY (`account_id`,`group_id`),
  KEY `FK_iam_account_group_group_id` (`group_id`),
  CONSTRAINT `FK_iam_account_group_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_account_group_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_group`
--

LOCK TABLES `iam_account_group` WRITE;
/*!40000 ALTER TABLE `iam_account_group` DISABLE KEYS */;
INSERT INTO `iam_account_group` VALUES (2,1,NULL,NULL),(2,2,NULL,NULL),(2,3,NULL,NULL),(10,1,NULL,NULL),(100,1,NULL,NULL),(100,2,NULL,NULL),(101,1,NULL,NULL),(101,2,NULL,NULL),(102,1,NULL,NULL),(102,2,NULL,NULL),(103,1,NULL,NULL),(103,2,NULL,NULL),(104,1,NULL,NULL),(104,2,NULL,NULL),(105,1,NULL,NULL),(105,2,NULL,NULL),(106,1,NULL,NULL),(106,2,NULL,NULL),(107,1,NULL,NULL),(107,2,NULL,NULL),(108,1,NULL,NULL),(108,2,NULL,NULL),(109,1,NULL,NULL),(109,2,NULL,NULL),(110,1,NULL,NULL),(110,2,NULL,NULL),(111,1,NULL,NULL),(111,2,NULL,NULL),(112,1,NULL,NULL),(112,2,NULL,NULL),(113,1,NULL,NULL),(113,2,NULL,NULL),(114,1,NULL,NULL),(114,2,NULL,NULL),(115,1,NULL,NULL),(115,2,NULL,NULL),(116,1,NULL,NULL),(116,2,NULL,NULL),(117,1,NULL,NULL),(117,2,NULL,NULL),(118,1,NULL,NULL),(118,2,NULL,NULL),(119,1,NULL,NULL),(119,2,NULL,NULL),(120,1,NULL,NULL),(120,2,NULL,NULL),(121,1,NULL,NULL),(121,2,NULL,NULL),(122,1,NULL,NULL),(122,2,NULL,NULL),(123,1,NULL,NULL),(123,2,NULL,NULL),(124,1,NULL,NULL),(124,2,NULL,NULL),(125,1,NULL,NULL),(125,2,NULL,NULL),(126,1,NULL,NULL),(126,2,NULL,NULL),(127,1,NULL,NULL),(127,2,NULL,NULL),(128,1,NULL,NULL),(128,2,NULL,NULL),(129,1,NULL,NULL),(129,2,NULL,NULL),(130,1,NULL,NULL),(130,2,NULL,NULL),(131,1,NULL,NULL),(131,2,NULL,NULL),(132,1,NULL,NULL),(132,2,NULL,NULL),(133,1,NULL,NULL),(133,2,NULL,NULL),(134,1,NULL,NULL),(134,2,NULL,NULL),(135,1,NULL,NULL),(135,2,NULL,NULL),(136,1,NULL,NULL),(136,2,NULL,NULL),(137,1,NULL,NULL),(137,2,NULL,NULL),(138,1,NULL,NULL),(138,2,NULL,NULL),(139,1,NULL,NULL),(139,2,NULL,NULL),(140,1,NULL,NULL),(140,2,NULL,NULL),(141,1,NULL,NULL),(141,2,NULL,NULL),(142,1,NULL,NULL),(142,2,NULL,NULL),(143,1,NULL,NULL),(143,2,NULL,NULL),(144,1,NULL,NULL),(144,2,NULL,NULL),(145,1,NULL,NULL),(145,2,NULL,NULL),(146,1,NULL,NULL),(146,2,NULL,NULL),(147,1,NULL,NULL),(147,2,NULL,NULL),(148,1,NULL,NULL),(148,2,NULL,NULL),(149,1,NULL,NULL),(149,2,NULL,NULL),(150,1,NULL,NULL),(150,2,NULL,NULL),(151,1,NULL,NULL),(151,2,NULL,NULL),(152,1,NULL,NULL),(152,2,NULL,NULL),(153,1,NULL,NULL),(153,2,NULL,NULL),(154,1,NULL,NULL),(154,2,NULL,NULL),(155,1,NULL,NULL),(155,2,NULL,NULL),(156,1,NULL,NULL),(156,2,NULL,NULL),(157,1,NULL,NULL),(157,2,NULL,NULL),(158,1,NULL,NULL),(158,2,NULL,NULL),(159,1,NULL,NULL),(159,2,NULL,NULL),(160,1,NULL,NULL),(160,2,NULL,NULL),(161,1,NULL,NULL),(161,2,NULL,NULL),(162,1,NULL,NULL),(162,2,NULL,NULL),(163,1,NULL,NULL),(163,2,NULL,NULL),(164,1,NULL,NULL),(164,2,NULL,NULL),(165,1,NULL,NULL),(165,2,NULL,NULL),(166,1,NULL,NULL),(166,2,NULL,NULL),(167,1,NULL,NULL),(167,2,NULL,NULL),(168,1,NULL,NULL),(168,2,NULL,NULL),(169,1,NULL,NULL),(169,2,NULL,NULL),(170,1,NULL,NULL),(170,2,NULL,NULL),(171,1,NULL,NULL),(171,2,NULL,NULL),(172,1,NULL,NULL),(172,2,NULL,NULL),(173,1,NULL,NULL),(173,2,NULL,NULL),(174,1,NULL,NULL),(174,2,NULL,NULL),(175,1,NULL,NULL),(175,2,NULL,NULL),(176,1,NULL,NULL),(176,2,NULL,NULL),(177,1,NULL,NULL),(177,2,NULL,NULL),(178,1,NULL,NULL),(178,2,NULL,NULL),(179,1,NULL,NULL),(179,2,NULL,NULL),(180,1,NULL,NULL),(180,2,NULL,NULL),(181,1,NULL,NULL),(181,2,NULL,NULL),(182,1,NULL,NULL),(182,2,NULL,NULL),(183,1,NULL,NULL),(183,2,NULL,NULL),(184,1,NULL,NULL),(184,2,NULL,NULL),(185,1,NULL,NULL),(185,2,NULL,NULL),(186,1,NULL,NULL),(186,2,NULL,NULL),(187,1,NULL,NULL),(187,2,NULL,NULL),(188,1,NULL,NULL),(188,2,NULL,NULL),(189,1,NULL,NULL),(189,2,NULL,NULL),(190,1,NULL,NULL),(190,2,NULL,NULL),(191,1,NULL,NULL),(191,2,NULL,NULL),(192,1,NULL,NULL),(192,2,NULL,NULL),(193,1,NULL,NULL),(193,2,NULL,NULL),(194,1,NULL,NULL),(194,2,NULL,NULL),(195,1,NULL,NULL),(195,2,NULL,NULL),(196,1,NULL,NULL),(196,2,NULL,NULL),(197,1,NULL,NULL),(197,2,NULL,NULL),(198,1,NULL,NULL),(198,2,NULL,NULL),(199,1,NULL,NULL),(199,2,NULL,NULL),(200,1,NULL,NULL),(200,2,NULL,NULL),(201,1,NULL,NULL),(201,2,NULL,NULL),(202,1,NULL,NULL),(202,2,NULL,NULL),(203,1,NULL,NULL),(203,2,NULL,NULL),(204,1,NULL,NULL),(204,2,NULL,NULL),(205,1,NULL,NULL),(205,2,NULL,NULL),(206,1,NULL,NULL),(206,2,NULL,NULL),(207,1,NULL,NULL),(207,2,NULL,NULL),(208,1,NULL,NULL),(208,2,NULL,NULL),(209,1,NULL,NULL),(209,2,NULL,NULL),(210,1,NULL,NULL),(210,2,NULL,NULL),(211,1,NULL,NULL),(211,2,NULL,NULL),(212,1,NULL,NULL),(212,2,NULL,NULL),(213,1,NULL,NULL),(213,2,NULL,NULL),(214,1,NULL,NULL),(214,2,NULL,NULL),(215,1,NULL,NULL),(215,2,NULL,NULL),(216,1,NULL,NULL),(216,2,NULL,NULL),(217,1,NULL,NULL),(217,2,NULL,NULL),(218,1,NULL,NULL),(218,2,NULL,NULL),(219,1,NULL,NULL),(219,2,NULL,NULL),(220,1,NULL,NULL),(220,2,NULL,NULL),(221,1,NULL,NULL),(221,2,NULL,NULL),(222,1,NULL,NULL),(222,2,NULL,NULL),(223,1,NULL,NULL),(223,2,NULL,NULL),(224,1,NULL,NULL),(224,2,NULL,NULL),(225,1,NULL,NULL),(225,2,NULL,NULL),(226,1,NULL,NULL),(226,2,NULL,NULL),(227,1,NULL,NULL),(227,2,NULL,NULL),(228,1,NULL,NULL),(228,2,NULL,NULL),(229,1,NULL,NULL),(229,2,NULL,NULL),(230,1,NULL,NULL),(230,2,NULL,NULL),(231,1,NULL,NULL),(231,2,NULL,NULL),(232,1,NULL,NULL),(232,2,NULL,NULL),(233,1,NULL,NULL),(233,2,NULL,NULL),(234,1,NULL,NULL),(234,2,NULL,NULL),(235,1,NULL,NULL),(235,2,NULL,NULL),(236,1,NULL,NULL),(236,2,NULL,NULL),(237,1,NULL,NULL),(237,2,NULL,NULL),(238,1,NULL,NULL),(238,2,NULL,NULL),(239,1,NULL,NULL),(239,2,NULL,NULL),(240,1,NULL,NULL),(240,2,NULL,NULL),(241,1,NULL,NULL),(241,2,NULL,NULL),(242,1,NULL,NULL),(242,2,NULL,NULL),(243,1,NULL,NULL),(243,2,NULL,NULL),(244,1,NULL,NULL),(244,2,NULL,NULL),(245,1,NULL,NULL),(245,2,NULL,NULL),(246,1,NULL,NULL),(246,2,NULL,NULL),(247,1,NULL,NULL),(247,2,NULL,NULL),(248,1,NULL,NULL),(248,2,NULL,NULL),(249,1,NULL,NULL),(249,2,NULL,NULL),(250,1,NULL,NULL),(250,2,NULL,NULL),(251,1,NULL,NULL),(251,2,NULL,NULL),(252,1,NULL,NULL),(252,2,NULL,NULL),(253,1,NULL,NULL),(253,2,NULL,NULL),(254,1,NULL,NULL),(254,2,NULL,NULL),(255,1,NULL,NULL),(255,2,NULL,NULL),(256,1,NULL,NULL),(256,2,NULL,NULL),(257,1,NULL,NULL),(257,2,NULL,NULL),(258,1,NULL,NULL),(258,2,NULL,NULL),(259,1,NULL,NULL),(259,2,NULL,NULL),(260,1,NULL,NULL),(260,2,NULL,NULL),(261,1,NULL,NULL),(261,2,NULL,NULL),(262,1,NULL,NULL),(262,2,NULL,NULL),(263,1,NULL,NULL),(263,2,NULL,NULL),(264,1,NULL,NULL),(264,2,NULL,NULL),(265,1,NULL,NULL),(265,2,NULL,NULL),(266,1,NULL,NULL),(266,2,NULL,NULL),(267,1,NULL,NULL),(267,2,NULL,NULL),(268,1,NULL,NULL),(268,2,NULL,NULL),(269,1,NULL,NULL),(269,2,NULL,NULL),(270,1,NULL,NULL),(270,2,NULL,NULL),(271,1,NULL,NULL),(271,2,NULL,NULL),(272,1,NULL,NULL),(272,2,NULL,NULL),(273,1,NULL,NULL),(273,2,NULL,NULL),(274,1,NULL,NULL),(274,2,NULL,NULL),(275,1,NULL,NULL),(275,2,NULL,NULL),(276,1,NULL,NULL),(276,2,NULL,NULL),(277,1,NULL,NULL),(277,2,NULL,NULL),(278,1,NULL,NULL),(278,2,NULL,NULL),(279,1,NULL,NULL),(279,2,NULL,NULL),(280,1,NULL,NULL),(280,2,NULL,NULL),(281,1,NULL,NULL),(281,2,NULL,NULL),(282,1,NULL,NULL),(282,2,NULL,NULL),(283,1,NULL,NULL),(283,2,NULL,NULL),(284,1,NULL,NULL),(284,2,NULL,NULL),(285,1,NULL,NULL),(285,2,NULL,NULL),(286,1,NULL,NULL),(286,2,NULL,NULL),(287,1,NULL,NULL),(287,2,NULL,NULL),(288,1,NULL,NULL),(288,2,NULL,NULL),(289,1,NULL,NULL),(289,2,NULL,NULL),(290,1,NULL,NULL),(290,2,NULL,NULL),(291,1,NULL,NULL),(291,2,NULL,NULL),(292,1,NULL,NULL),(292,2,NULL,NULL),(293,1,NULL,NULL),(293,2,NULL,NULL),(294,1,NULL,NULL),(294,2,NULL,NULL),(295,1,NULL,NULL),(295,2,NULL,NULL),(296,1,NULL,NULL),(296,2,NULL,NULL),(297,1,NULL,NULL),(297,2,NULL,NULL),(298,1,NULL,NULL),(298,2,NULL,NULL),(299,1,NULL,NULL),(299,2,NULL,NULL),(300,1,NULL,NULL),(300,2,NULL,NULL),(301,1,NULL,NULL),(301,2,NULL,NULL),(302,1,NULL,NULL),(302,2,NULL,NULL),(303,1,NULL,NULL),(303,2,NULL,NULL),(304,1,NULL,NULL),(304,2,NULL,NULL),(305,1,NULL,NULL),(305,2,NULL,NULL),(306,1,NULL,NULL),(306,2,NULL,NULL),(307,1,NULL,NULL),(307,2,NULL,NULL),(308,1,NULL,NULL),(308,2,NULL,NULL),(309,1,NULL,NULL),(309,2,NULL,NULL),(310,1,NULL,NULL),(310,2,NULL,NULL),(311,1,NULL,NULL),(311,2,NULL,NULL),(312,1,NULL,NULL),(312,2,NULL,NULL),(313,1,NULL,NULL),(313,2,NULL,NULL),(314,1,NULL,NULL),(314,2,NULL,NULL),(315,1,NULL,NULL),(315,2,NULL,NULL),(316,1,NULL,NULL),(316,2,NULL,NULL),(317,1,NULL,NULL),(317,2,NULL,NULL),(318,1,NULL,NULL),(318,2,NULL,NULL),(319,1,NULL,NULL),(319,2,NULL,NULL),(320,1,NULL,NULL),(320,2,NULL,NULL),(321,1,NULL,NULL),(321,2,NULL,NULL),(322,1,NULL,NULL),(322,2,NULL,NULL),(323,1,NULL,NULL),(323,2,NULL,NULL),(324,1,NULL,NULL),(324,2,NULL,NULL),(325,1,NULL,NULL),(325,2,NULL,NULL),(326,1,NULL,NULL),(326,2,NULL,NULL),(327,1,NULL,NULL),(327,2,NULL,NULL),(328,1,NULL,NULL),(328,2,NULL,NULL),(329,1,NULL,NULL),(329,2,NULL,NULL),(330,1,NULL,NULL),(330,2,NULL,NULL),(331,1,NULL,NULL),(331,2,NULL,NULL),(332,1,NULL,NULL),(332,2,NULL,NULL),(333,1,NULL,NULL),(333,2,NULL,NULL),(334,1,NULL,NULL),(334,2,NULL,NULL),(335,1,NULL,NULL),(335,2,NULL,NULL),(336,1,NULL,NULL),(336,2,NULL,NULL),(337,1,NULL,NULL),(337,2,NULL,NULL),(338,1,NULL,NULL),(338,2,NULL,NULL),(339,1,NULL,NULL),(339,2,NULL,NULL),(340,1,NULL,NULL),(340,2,NULL,NULL),(341,1,NULL,NULL),(341,2,NULL,NULL),(342,1,NULL,NULL),(342,2,NULL,NULL),(343,1,NULL,NULL),(343,2,NULL,NULL),(344,1,NULL,NULL),(344,2,NULL,NULL),(345,1,NULL,NULL),(345,2,NULL,NULL),(346,1,NULL,NULL),(346,2,NULL,NULL),(347,1,NULL,NULL),(347,2,NULL,NULL);
/*!40000 ALTER TABLE `iam_account_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_labels`
--

DROP TABLE IF EXISTS `iam_account_labels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_labels` (
  `NAME` varchar(64) NOT NULL,
  `PREFIX` varchar(256) DEFAULT NULL,
  `val` varchar(64) DEFAULT NULL,
  `account_id` bigint DEFAULT NULL,
  KEY `INDEX_iam_account_labels_prefix_name_val` (`PREFIX`,`NAME`,`val`),
  KEY `INDEX_iam_account_labels_prefix_name` (`PREFIX`,`NAME`),
  KEY `FK_iam_account_labels_account_id` (`account_id`),
  CONSTRAINT `FK_iam_account_labels_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_labels`
--

LOCK TABLES `iam_account_labels` WRITE;
/*!40000 ALTER TABLE `iam_account_labels` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_account_labels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_login_lockout`
--

DROP TABLE IF EXISTS `iam_account_login_lockout`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_account_login_lockout` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `account_id` bigint NOT NULL,
  `failed_attempts` int NOT NULL DEFAULT '0',
  `first_failure_time` timestamp NULL DEFAULT NULL,
  `lockout_count` int NOT NULL DEFAULT '0',
  `suspended_until` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UK_iam_login_lockout_account` (`account_id`),
  CONSTRAINT `FK_iam_login_lockout_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_login_lockout`
--

LOCK TABLES `iam_account_login_lockout` WRITE;
/*!40000 ALTER TABLE `iam_account_login_lockout` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_account_login_lockout` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_address`
--

DROP TABLE IF EXISTS `iam_address`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_address` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `COUNTRY` varchar(2) DEFAULT NULL,
  `FORMATTED` varchar(128) DEFAULT NULL,
  `LOCALITY` varchar(128) DEFAULT NULL,
  `POSTALCODE` varchar(16) DEFAULT NULL,
  `REGION` varchar(128) DEFAULT NULL,
  `STREETADDRESS` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_address`
--

LOCK TABLES `iam_address` WRITE;
/*!40000 ALTER TABLE `iam_address` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_address` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_aup`
--

DROP TABLE IF EXISTS `iam_aup`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_aup` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `description` varchar(128) DEFAULT NULL,
  `last_update_time` datetime NOT NULL,
  `name` varchar(36) NOT NULL,
  `sig_validity_days` bigint NOT NULL,
  `text` longtext,
  `url` varchar(256) DEFAULT NULL,
  `aup_reminders_days` varchar(128) NOT NULL DEFAULT '30,15,1',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_aup`
--

LOCK TABLES `iam_aup` WRITE;
/*!40000 ALTER TABLE `iam_aup` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_aup` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_aup_signature`
--

DROP TABLE IF EXISTS `iam_aup_signature`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_aup_signature` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `signature_time` datetime NOT NULL,
  `account_id` bigint DEFAULT NULL,
  `aup_id` bigint DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UNQ_iam_aup_signature_0` (`aup_id`,`account_id`),
  KEY `FK_iam_aup_signature_account_id` (`account_id`),
  CONSTRAINT `FK_iam_aup_signature_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_aup_signature_aup_id` FOREIGN KEY (`aup_id`) REFERENCES `iam_aup` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_aup_signature`
--

LOCK TABLES `iam_aup_signature` WRITE;
/*!40000 ALTER TABLE `iam_aup_signature` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_aup_signature` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_authority`
--

DROP TABLE IF EXISTS `iam_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_authority` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `auth` varchar(128) NOT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `auth` (`auth`)
) ENGINE=InnoDB AUTO_INCREMENT=28 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_authority`
--

LOCK TABLES `iam_authority` WRITE;
/*!40000 ALTER TABLE `iam_authority` DISABLE KEYS */;
INSERT INTO `iam_authority` VALUES (1,'ROLE_ADMIN'),(7,'ROLE_GM:31d9230c-90ae-4457-a990-0c443ab4aacc'),(6,'ROLE_GM:6a384bcd-d4b3-4b7f-a2fe-7d897ada0dd1'),(8,'ROLE_GM:c617d586-54e6-411d-8e38-649677980001'),(9,'ROLE_GM:c617d586-54e6-411d-8e38-649677980002'),(10,'ROLE_GM:c617d586-54e6-411d-8e38-649677980003'),(11,'ROLE_GM:c617d586-54e6-411d-8e38-649677980004'),(12,'ROLE_GM:c617d586-54e6-411d-8e38-649677980005'),(13,'ROLE_GM:c617d586-54e6-411d-8e38-649677980006'),(14,'ROLE_GM:c617d586-54e6-411d-8e38-649677980007'),(15,'ROLE_GM:c617d586-54e6-411d-8e38-649677980008'),(16,'ROLE_GM:c617d586-54e6-411d-8e38-649677980009'),(17,'ROLE_GM:c617d586-54e6-411d-8e38-649677980010'),(18,'ROLE_GM:c617d586-54e6-411d-8e38-649677980011'),(19,'ROLE_GM:c617d586-54e6-411d-8e38-649677980012'),(20,'ROLE_GM:c617d586-54e6-411d-8e38-649677980013'),(21,'ROLE_GM:c617d586-54e6-411d-8e38-649677980014'),(22,'ROLE_GM:c617d586-54e6-411d-8e38-649677980015'),(23,'ROLE_GM:c617d586-54e6-411d-8e38-649677980016'),(24,'ROLE_GM:c617d586-54e6-411d-8e38-649677980017'),(25,'ROLE_GM:c617d586-54e6-411d-8e38-649677980018'),(26,'ROLE_GM:c617d586-54e6-411d-8e38-649677980019'),(27,'ROLE_GM:c617d586-54e6-411d-8e38-649677980020'),(5,'ROLE_GM:c617d586-54e6-411d-8e38-64967798fa8a'),(3,'ROLE_PRE_AUTHENTICATED'),(4,'ROLE_READER'),(2,'ROLE_USER');
/*!40000 ALTER TABLE `iam_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_email_notification`
--

DROP TABLE IF EXISTS `iam_email_notification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_email_notification` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `UUID` varchar(36) NOT NULL,
  `NOTIFICATION_TYPE` varchar(128) NOT NULL,
  `SUBJECT` varchar(128) DEFAULT NULL,
  `BODY` text,
  `CREATION_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `DELIVERY_STATUS` varchar(128) DEFAULT NULL,
  `LAST_UPDATE` timestamp NULL DEFAULT NULL,
  `REQUEST_ID` bigint DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_email_notification_request_id` (`REQUEST_ID`),
  CONSTRAINT `FK_iam_email_notification_request_id` FOREIGN KEY (`REQUEST_ID`) REFERENCES `iam_reg_request` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_email_notification`
--

LOCK TABLES `iam_email_notification` WRITE;
/*!40000 ALTER TABLE `iam_email_notification` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_email_notification` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_exchange_policy`
--

DROP TABLE IF EXISTS `iam_exchange_policy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_exchange_policy` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `description` varchar(512) DEFAULT NULL,
  `last_update_time` datetime NOT NULL,
  `rule` varchar(6) NOT NULL,
  `dest_m_param` varchar(256) DEFAULT NULL,
  `dest_m_type` varchar(8) NOT NULL,
  `origin_m_param` varchar(256) DEFAULT NULL,
  `origin_m_type` varchar(8) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_exchange_policy`
--

LOCK TABLES `iam_exchange_policy` WRITE;
/*!40000 ALTER TABLE `iam_exchange_policy` DISABLE KEYS */;
INSERT INTO `iam_exchange_policy` VALUES (1,'2026-11-23 14:40:54','Allow all exchanges','2026-11-23 14:40:54','PERMIT',NULL,'ANY',NULL,'ANY');
/*!40000 ALTER TABLE `iam_exchange_policy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_exchange_scope_policies`
--

DROP TABLE IF EXISTS `iam_exchange_scope_policies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_exchange_scope_policies` (
  `param` varchar(256) DEFAULT NULL,
  `rule` varchar(6) NOT NULL,
  `type` varchar(6) NOT NULL,
  `exchange_policy_id` bigint DEFAULT NULL,
  KEY `FK_iam_exchange_scope_policies_exchange_policy_id` (`exchange_policy_id`),
  CONSTRAINT `FK_iam_exchange_scope_policies_exchange_policy_id` FOREIGN KEY (`exchange_policy_id`) REFERENCES `iam_exchange_policy` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_exchange_scope_policies`
--

LOCK TABLES `iam_exchange_scope_policies` WRITE;
/*!40000 ALTER TABLE `iam_exchange_scope_policies` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_exchange_scope_policies` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_ext_authn`
--

DROP TABLE IF EXISTS `iam_ext_authn`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_ext_authn` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `authentication_time` datetime NOT NULL,
  `expiration_time` datetime NOT NULL,
  `saved_authn_id` bigint DEFAULT NULL,
  `type` varchar(32) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `saved_authn_id` (`saved_authn_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_ext_authn`
--

LOCK TABLES `iam_ext_authn` WRITE;
/*!40000 ALTER TABLE `iam_ext_authn` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_ext_authn` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_ext_authn_attr`
--

DROP TABLE IF EXISTS `iam_ext_authn_attr`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_ext_authn_attr` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `value` varchar(512) NOT NULL,
  `details_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_iam_ext_authn_attr_details_id` (`details_id`),
  CONSTRAINT `FK_iam_ext_authn_attr_details_id` FOREIGN KEY (`details_id`) REFERENCES `iam_ext_authn` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_ext_authn_attr`
--

LOCK TABLES `iam_ext_authn_attr` WRITE;
/*!40000 ALTER TABLE `iam_ext_authn_attr` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_ext_authn_attr` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_federated_client`
--

DROP TABLE IF EXISTS `iam_federated_client`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_federated_client` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `client_id` varchar(256) NOT NULL,
  `client_secret` text,
  `client_name` varchar(256) NOT NULL,
  `token_endpoint_auth_method` varchar(256) DEFAULT NULL,
  `jwks_uri` text,
  `jwks` text,
  `created_at` timestamp NULL DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  `expiration` timestamp NOT NULL,
  `entity_id` varchar(512) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `entity_id` (`entity_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_federated_client`
--

LOCK TABLES `iam_federated_client` WRITE;
/*!40000 ALTER TABLE `iam_federated_client` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_federated_client` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_federated_client_grant_type`
--

DROP TABLE IF EXISTS `iam_federated_client_grant_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_federated_client_grant_type` (
  `owner_id` bigint NOT NULL,
  `grant_type` varchar(2000) NOT NULL,
  KEY `fk_iam_federated_client_grant_type` (`owner_id`),
  CONSTRAINT `fk_iam_federated_client_grant_type` FOREIGN KEY (`owner_id`) REFERENCES `iam_federated_client` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_federated_client_grant_type`
--

LOCK TABLES `iam_federated_client_grant_type` WRITE;
/*!40000 ALTER TABLE `iam_federated_client_grant_type` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_federated_client_grant_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_federated_client_redirect_uri`
--

DROP TABLE IF EXISTS `iam_federated_client_redirect_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_federated_client_redirect_uri` (
  `owner_id` bigint NOT NULL,
  `redirect_uri` varchar(2048) NOT NULL,
  KEY `fk_iam_federated_client_redirect_uri` (`owner_id`),
  CONSTRAINT `fk_iam_federated_client_redirect_uri` FOREIGN KEY (`owner_id`) REFERENCES `iam_federated_client` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_federated_client_redirect_uri`
--

LOCK TABLES `iam_federated_client_redirect_uri` WRITE;
/*!40000 ALTER TABLE `iam_federated_client_redirect_uri` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_federated_client_redirect_uri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_federated_client_response_type`
--

DROP TABLE IF EXISTS `iam_federated_client_response_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_federated_client_response_type` (
  `owner_id` bigint NOT NULL,
  `response_type` varchar(2000) NOT NULL,
  KEY `fk_iam_federated_client_response_type` (`owner_id`),
  CONSTRAINT `fk_iam_federated_client_response_type` FOREIGN KEY (`owner_id`) REFERENCES `iam_federated_client` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_federated_client_response_type`
--

LOCK TABLES `iam_federated_client_response_type` WRITE;
/*!40000 ALTER TABLE `iam_federated_client_response_type` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_federated_client_response_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_federated_client_scope`
--

DROP TABLE IF EXISTS `iam_federated_client_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_federated_client_scope` (
  `owner_id` bigint NOT NULL,
  `scope` varchar(2048) NOT NULL,
  KEY `fk_iam_federated_client_scope` (`owner_id`),
  CONSTRAINT `fk_iam_federated_client_scope` FOREIGN KEY (`owner_id`) REFERENCES `iam_federated_client` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_federated_client_scope`
--

LOCK TABLES `iam_federated_client_scope` WRITE;
/*!40000 ALTER TABLE `iam_federated_client_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_federated_client_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group`
--

DROP TABLE IF EXISTS `iam_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_group` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `CREATIONTIME` datetime NOT NULL,
  `DESCRIPTION` varchar(512) DEFAULT NULL,
  `LASTUPDATETIME` datetime NOT NULL,
  `name` varchar(512) NOT NULL,
  `UUID` varchar(36) NOT NULL,
  `parent_group_id` bigint DEFAULT NULL,
  `default_group` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `NAME` (`name`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_group_parent_id` (`parent_group_id`),
  CONSTRAINT `FK_iam_group_parent_id` FOREIGN KEY (`parent_group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=121 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_group`
--

LOCK TABLES `iam_group` WRITE;
/*!40000 ALTER TABLE `iam_group` DISABLE KEYS */;
INSERT INTO `iam_group` VALUES (1,'2026-11-23 14:41:08','The production group','2026-11-23 14:41:08','Production','c617d586-54e6-411d-8e38-64967798fa8a',NULL,0),(2,'2026-11-23 14:41:08','The analysis group','2026-11-23 14:41:08','Analysis','6a384bcd-d4b3-4b7f-a2fe-7d897ada0dd1',NULL,0),(3,'2026-11-23 14:41:08','The optional group','2026-11-23 14:41:08','Optional','31d9230c-90ae-4457-a990-0c443ab4aacc',NULL,0),(101,'2026-11-23 14:41:08','Test group-001','2026-11-23 14:41:08','Test-001','c617d586-54e6-411d-8e38-649677980001',NULL,0),(102,'2026-11-23 14:41:08','Test group-002','2026-11-23 14:41:08','Test-002','c617d586-54e6-411d-8e38-649677980002',NULL,0),(103,'2026-11-23 14:41:08','Test group-003','2026-11-23 14:41:08','Test-003','c617d586-54e6-411d-8e38-649677980003',NULL,0),(104,'2026-11-23 14:41:08','Test group-004','2026-11-23 14:41:08','Test-004','c617d586-54e6-411d-8e38-649677980004',NULL,0),(105,'2026-11-23 14:41:08','Test group-005','2026-11-23 14:41:08','Test-005','c617d586-54e6-411d-8e38-649677980005',NULL,0),(106,'2026-11-23 14:41:08','Test group-006','2026-11-23 14:41:08','Test-006','c617d586-54e6-411d-8e38-649677980006',NULL,0),(107,'2026-11-23 14:41:08','Test group-007','2026-11-23 14:41:08','Test-007','c617d586-54e6-411d-8e38-649677980007',NULL,0),(108,'2026-11-23 14:41:08','Test group-008','2026-11-23 14:41:08','Test-008','c617d586-54e6-411d-8e38-649677980008',NULL,0),(109,'2026-11-23 14:41:08','Test group-009','2026-11-23 14:41:08','Test-009','c617d586-54e6-411d-8e38-649677980009',NULL,0),(110,'2026-11-23 14:41:08','Test group-010','2026-11-23 14:41:08','Test-010','c617d586-54e6-411d-8e38-649677980010',NULL,0),(111,'2026-11-23 14:41:08','Test group-011','2026-11-23 14:41:08','Test-011','c617d586-54e6-411d-8e38-649677980011',NULL,0),(112,'2026-11-23 14:41:08','Test group-012','2026-11-23 14:41:08','Test-012','c617d586-54e6-411d-8e38-649677980012',NULL,0),(113,'2026-11-23 14:41:08','Test group-013','2026-11-23 14:41:08','Test-013','c617d586-54e6-411d-8e38-649677980013',NULL,0),(114,'2026-11-23 14:41:08','Test group-014','2026-11-23 14:41:08','Test-014','c617d586-54e6-411d-8e38-649677980014',NULL,0),(115,'2026-11-23 14:41:08','Test group-015','2026-11-23 14:41:08','Test-015','c617d586-54e6-411d-8e38-649677980015',NULL,0),(116,'2026-11-23 14:41:08','Test group-016','2026-11-23 14:41:08','Test-016','c617d586-54e6-411d-8e38-649677980016',NULL,0),(117,'2026-11-23 14:41:08','Test group-017','2026-11-23 14:41:08','Test-017','c617d586-54e6-411d-8e38-649677980017',NULL,0),(118,'2026-11-23 14:41:08','Test group-018','2026-11-23 14:41:08','Test-018','c617d586-54e6-411d-8e38-649677980018',NULL,0),(119,'2026-11-23 14:41:08','Test group-019','2026-11-23 14:41:08','Test-019','c617d586-54e6-411d-8e38-649677980019',NULL,0),(120,'2026-11-23 14:41:08','Test group-020','2026-11-23 14:41:08','Test-020','c617d586-54e6-411d-8e38-649677980020',NULL,0);
/*!40000 ALTER TABLE `iam_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group_attrs`
--

DROP TABLE IF EXISTS `iam_group_attrs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_group_attrs` (
  `NAME` varchar(64) NOT NULL,
  `val` varchar(256) DEFAULT NULL,
  `group_id` bigint DEFAULT NULL,
  KEY `INDEX_iam_group_attrs_name` (`NAME`),
  KEY `INDEX_iam_group_attrs_name_val` (`NAME`,`val`),
  KEY `FK_iam_group_attrs_group_id` (`group_id`),
  CONSTRAINT `FK_iam_group_attrs_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_group_attrs`
--

LOCK TABLES `iam_group_attrs` WRITE;
/*!40000 ALTER TABLE `iam_group_attrs` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_group_attrs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group_labels`
--

DROP TABLE IF EXISTS `iam_group_labels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_group_labels` (
  `NAME` varchar(64) NOT NULL,
  `PREFIX` varchar(256) DEFAULT NULL,
  `val` varchar(64) DEFAULT NULL,
  `group_id` bigint DEFAULT NULL,
  KEY `INDEX_iam_group_labels_prefix_name_val` (`PREFIX`,`NAME`,`val`),
  KEY `INDEX_iam_group_labels_prefix_name` (`PREFIX`,`NAME`),
  KEY `FK_iam_group_labels_group_id` (`group_id`),
  CONSTRAINT `FK_iam_group_labels_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_group_labels`
--

LOCK TABLES `iam_group_labels` WRITE;
/*!40000 ALTER TABLE `iam_group_labels` DISABLE KEYS */;
INSERT INTO `iam_group_labels` VALUES ('wlcg.optional-group',NULL,NULL,3);
/*!40000 ALTER TABLE `iam_group_labels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group_request`
--

DROP TABLE IF EXISTS `iam_group_request`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_group_request` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `UUID` varchar(36) NOT NULL,
  `ACCOUNT_ID` bigint DEFAULT NULL,
  `GROUP_ID` bigint DEFAULT NULL,
  `STATUS` varchar(50) DEFAULT NULL,
  `NOTES` text,
  `MOTIVATION` text,
  `CREATIONTIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `LASTUPDATETIME` timestamp NULL DEFAULT '2000-01-01 00:00:00',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_group_request_account_id` (`ACCOUNT_ID`),
  KEY `FK_iam_group_request_group_id` (`GROUP_ID`),
  CONSTRAINT `FK_iam_group_request_account_id` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_group_request_group_id` FOREIGN KEY (`GROUP_ID`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_group_request`
--

LOCK TABLES `iam_group_request` WRITE;
/*!40000 ALTER TABLE `iam_group_request` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_group_request` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_notification_receiver`
--

DROP TABLE IF EXISTS `iam_notification_receiver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_notification_receiver` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `NOTIFICATION_ID` bigint DEFAULT NULL,
  `EMAIL_ADDRESS` varchar(254) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_notification_receiver_notification_id` (`NOTIFICATION_ID`),
  CONSTRAINT `FK_iam_notification_receiver_notification_id` FOREIGN KEY (`NOTIFICATION_ID`) REFERENCES `iam_email_notification` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_notification_receiver`
--

LOCK TABLES `iam_notification_receiver` WRITE;
/*!40000 ALTER TABLE `iam_notification_receiver` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_notification_receiver` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_oidc_id`
--

DROP TABLE IF EXISTS `iam_oidc_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_oidc_id` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `ISSUER` varchar(256) NOT NULL,
  `SUBJECT` varchar(256) NOT NULL,
  `account_id` bigint DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_oidc_id_account_id` (`account_id`),
  CONSTRAINT `FK_iam_oidc_id_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_oidc_id`
--

LOCK TABLES `iam_oidc_id` WRITE;
/*!40000 ALTER TABLE `iam_oidc_id` DISABLE KEYS */;
INSERT INTO `iam_oidc_id` VALUES (1,'https://accounts.google.com','114132403455520317223',1),(2,'https://accounts.google.com','105440632287425289613',2),(3,'urn:test-oidc-issuer','test-user',2),(4,'urn:test-oidc-issuer','test-with-mfa',1000);
/*!40000 ALTER TABLE `iam_oidc_id` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_reg_request`
--

DROP TABLE IF EXISTS `iam_reg_request`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_reg_request` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `UUID` varchar(36) NOT NULL,
  `CREATIONTIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ACCOUNT_ID` bigint DEFAULT NULL,
  `STATUS` varchar(50) DEFAULT NULL,
  `LASTUPDATETIME` timestamp NULL DEFAULT NULL,
  `notes` text,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_reg_request_account_id` (`ACCOUNT_ID`),
  CONSTRAINT `FK_iam_reg_request_account_id` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_reg_request`
--

LOCK TABLES `iam_reg_request` WRITE;
/*!40000 ALTER TABLE `iam_reg_request` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_reg_request` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_reg_request_labels`
--

DROP TABLE IF EXISTS `iam_reg_request_labels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_reg_request_labels` (
  `NAME` varchar(64) NOT NULL,
  `PREFIX` varchar(256) DEFAULT NULL,
  `val` varchar(64) DEFAULT NULL,
  `request_id` bigint DEFAULT NULL,
  KEY `INDEX_iam_reg_request_labels_prefix_name_val` (`PREFIX`,`NAME`,`val`),
  KEY `INDEX_iam_reg_request_labels_prefix_name` (`PREFIX`,`NAME`),
  KEY `FK_iam_reg_request_labels_request_id` (`request_id`),
  CONSTRAINT `FK_iam_reg_request_labels_request_id` FOREIGN KEY (`request_id`) REFERENCES `iam_reg_request` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_reg_request_labels`
--

LOCK TABLES `iam_reg_request_labels` WRITE;
/*!40000 ALTER TABLE `iam_reg_request_labels` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_reg_request_labels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_revoked_at`
--

DROP TABLE IF EXISTS `iam_revoked_at`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_revoked_at` (
  `hash_value` char(64) NOT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  `revoked_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`hash_value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci ROW_FORMAT=DYNAMIC;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_revoked_at`
--

LOCK TABLES `iam_revoked_at` WRITE;
/*!40000 ALTER TABLE `iam_revoked_at` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_revoked_at` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_saml_id`
--

DROP TABLE IF EXISTS `iam_saml_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_saml_id` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `IDPID` varchar(256) NOT NULL,
  `USERID` varchar(256) NOT NULL,
  `account_id` bigint DEFAULT NULL,
  `attribute_id` varchar(256) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_saml_id_account_id` (`account_id`),
  KEY `IDX_IAM_SAML_ID_1` (`IDPID`,`attribute_id`,`USERID`),
  CONSTRAINT `FK_iam_saml_id_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_saml_id`
--

LOCK TABLES `iam_saml_id` WRITE;
/*!40000 ALTER TABLE `iam_saml_id` DISABLE KEYS */;
INSERT INTO `iam_saml_id` VALUES (1,'https://idptestbed/idp/shibboleth','admin@example.org',1,'urn:oid:1.3.6.1.4.1.5923.1.1.1.13'),(2,'https://idptestbed/idp/shibboleth','andrea.ceccanti@example.org',2,'urn:oid:0.9.2342.19200300.100.1.3'),(3,'https://idptestbed/idp/shibboleth','78901@idptestbed',2,'urn:oid:1.3.6.1.4.1.5923.1.1.1.13');
/*!40000 ALTER TABLE `iam_saml_id` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_scope_policy`
--

DROP TABLE IF EXISTS `iam_scope_policy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_scope_policy` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `description` varchar(512) DEFAULT NULL,
  `last_update_time` datetime NOT NULL,
  `rule` varchar(6) NOT NULL,
  `account_id` bigint DEFAULT NULL,
  `group_id` bigint DEFAULT NULL,
  `matching_policy` varchar(6) NOT NULL DEFAULT 'EQ',
  PRIMARY KEY (`ID`),
  KEY `FK_iam_scope_policy_group_id` (`group_id`),
  KEY `FK_iam_scope_policy_account_id` (`account_id`),
  CONSTRAINT `FK_iam_scope_policy_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_scope_policy_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=1006 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_scope_policy`
--

LOCK TABLES `iam_scope_policy` WRITE;
/*!40000 ALTER TABLE `iam_scope_policy` DISABLE KEYS */;
INSERT INTO `iam_scope_policy` VALUES (1,'2026-11-23 14:40:48','Default Permit ALL policy','2026-11-23 14:40:48','PERMIT',NULL,NULL,'EQ'),(2,'2026-11-23 14:48:57','Allow access to storage scopes to admin user','2026-11-23 14:48:57','PERMIT',1,NULL,'PATH'),(3,'2026-11-23 15:04:05','Test storage restriction','2026-11-23 15:04:05','PERMIT',2,NULL,'PATH'),(4,'2026-11-23 15:10:51','Test storage restriction','2026-11-23 15:10:51','PERMIT',2,NULL,'PATH'),(5,'2026-11-23 15:11:45','Test storage restriction','2026-11-23 15:11:45','PERMIT',2,NULL,'PATH'),(6,'2026-11-23 15:12:38','Test storage restriction','2026-11-23 15:12:38','PERMIT',2,NULL,'PATH'),(7,'2026-11-23 15:12:38','Test storage restriction','2026-11-23 15:12:38','PERMIT',2,NULL,'PATH'),(8,'2026-11-23 15:12:38','Test storage restriction','2026-11-23 15:12:38','PERMIT',2,NULL,'PATH'),(9,'2026-11-23 15:12:38','Test storage restriction','2026-11-23 15:12:38','PERMIT',2,NULL,'PATH'),(10,'2026-11-23 15:12:38','Test storage restriction','2026-11-23 15:12:38','PERMIT',2,NULL,'PATH'),(11,'2026-11-23 15:12:38','Test storage restriction','2026-11-23 15:12:38','PERMIT',2,NULL,'PATH'),(12,'2026-11-23 15:12:38','Test storage restriction','2026-11-23 15:12:38','PERMIT',2,NULL,'PATH'),(13,'2026-11-23 15:12:38','Test storage restriction','2026-11-23 15:12:38','PERMIT',2,NULL,'PATH'),(14,'2026-11-23 15:12:38','Test storage restriction','2026-11-23 15:12:38','PERMIT',2,NULL,'PATH'),(15,'2026-11-23 15:12:38','Test storage restriction','2026-11-23 15:12:38','PERMIT',2,NULL,'PATH'),(16,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(17,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(18,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(19,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(20,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(21,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(22,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(23,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(24,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(25,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(26,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(27,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(28,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(29,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(30,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(31,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(32,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(33,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(34,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(35,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(36,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(37,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(38,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(39,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(40,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(41,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(42,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(43,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(44,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(45,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(46,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(47,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(48,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(49,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(50,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(51,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(52,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(53,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(54,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(55,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(56,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(57,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(58,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(59,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(60,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(61,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(62,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(63,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(64,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(65,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(66,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(67,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(68,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(69,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(70,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(71,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(72,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(73,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(74,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(75,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(76,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(77,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(78,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(79,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(80,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(81,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(82,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(83,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(84,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(85,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(86,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(87,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(88,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(89,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(90,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(91,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(92,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(93,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(94,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(95,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(96,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(97,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(98,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(99,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(100,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(101,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(102,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(103,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(104,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(105,'2026-11-23 18:23:52','Test storage restriction','2026-11-23 18:23:52','PERMIT',2,NULL,'PATH'),(106,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(107,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(108,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(109,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(110,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(111,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(112,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(113,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(114,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(115,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(116,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(117,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(118,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(119,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(120,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(121,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(122,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(123,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(124,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(125,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(126,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(127,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(128,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(129,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(130,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(131,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(132,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(133,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(134,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(135,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(136,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(137,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(138,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(139,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(140,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(141,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(142,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(143,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(144,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(145,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(146,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(147,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(148,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(149,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(150,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(151,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(152,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(153,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(154,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(155,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(156,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(157,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(158,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(159,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(160,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(161,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(162,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(163,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(164,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(165,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(166,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(167,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(168,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(169,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(170,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(171,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(172,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(173,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(174,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(175,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(176,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(177,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(178,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(179,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(180,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(181,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(182,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(183,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(184,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(185,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(186,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(187,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(188,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(189,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(190,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(191,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(192,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(193,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(194,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(195,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(196,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(197,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(198,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(199,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(200,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(201,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(202,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(203,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(204,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(205,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(206,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(207,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(208,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(209,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(210,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(211,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(212,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(213,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(214,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(215,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(216,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(217,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(218,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(219,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(220,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(221,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(222,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(223,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(224,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(225,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(226,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(227,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(228,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(229,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(230,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(231,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(232,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(233,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(234,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(235,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(236,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(237,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(238,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(239,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(240,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(241,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(242,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(243,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(244,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(245,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(246,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(247,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(248,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(249,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(250,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(251,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(252,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(253,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(254,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(255,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(256,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(257,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(258,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(259,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(260,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(261,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(262,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(263,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(264,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(265,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(266,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(267,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(268,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(269,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(270,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(271,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(272,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(273,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(274,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(275,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(276,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(277,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(278,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(279,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(280,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(281,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(282,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(283,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(284,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(285,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(286,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(287,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(288,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(289,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(290,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(291,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(292,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(293,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(294,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(295,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(296,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(297,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(298,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(299,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(300,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(301,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(302,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(303,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(304,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(305,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(306,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(307,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(308,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(309,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(310,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(311,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(312,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(313,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(314,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(315,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(316,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(317,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(318,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(319,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(320,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(321,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(322,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(323,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(324,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(325,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(326,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(327,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(328,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(329,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(330,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(331,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(332,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(333,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(334,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(335,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(336,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(337,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(338,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(339,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(340,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(341,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(342,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(343,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(344,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(345,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(346,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(347,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(348,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(349,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(350,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(351,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(352,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(353,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(354,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(355,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(356,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(357,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(358,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(359,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(360,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(361,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(362,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(363,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(364,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(365,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(366,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(367,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(368,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(369,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(370,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(371,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(372,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(373,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(374,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(375,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(376,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(377,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(378,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(379,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(380,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(381,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(382,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(383,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(384,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(385,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(386,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(387,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(388,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(389,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(390,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(391,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(392,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(393,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(394,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(395,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(396,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(397,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(398,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(399,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(400,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(401,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(402,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(403,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(404,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(405,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(406,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(407,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(408,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(409,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(410,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(411,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(412,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(413,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(414,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(415,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(416,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(417,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(418,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(419,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(420,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(421,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(422,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(423,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(424,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(425,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(426,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(427,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(428,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(429,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(430,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(431,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(432,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(433,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(434,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(435,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(436,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(437,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(438,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(439,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(440,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(441,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(442,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(443,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(444,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(445,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(446,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(447,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(448,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(449,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(450,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(451,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(452,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(453,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(454,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(455,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(456,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(457,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(458,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(459,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(460,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(461,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(462,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(463,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(464,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(465,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(466,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(467,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(468,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(469,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(470,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(471,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(472,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(473,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(474,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(475,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(476,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(477,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(478,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(479,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(480,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(481,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(482,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(483,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(484,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(485,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(486,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(487,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(488,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(489,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(490,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(491,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(492,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(493,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(494,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(495,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(496,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(497,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(498,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(499,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(500,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(501,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(502,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(503,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(504,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(505,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(506,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(507,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(508,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(509,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(510,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(511,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(512,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(513,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(514,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(515,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(516,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(517,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(518,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(519,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(520,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(521,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(522,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(523,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(524,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(525,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(526,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(527,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(528,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(529,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(530,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(531,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(532,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(533,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(534,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(535,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(536,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(537,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(538,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(539,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(540,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(541,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(542,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(543,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(544,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(545,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(546,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(547,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(548,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(549,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(550,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(551,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(552,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(553,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(554,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(555,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(556,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(557,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(558,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(559,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(560,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(561,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(562,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(563,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(564,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(565,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(566,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(567,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(568,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(569,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(570,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(571,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(572,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(573,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(574,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(575,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(576,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(577,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(578,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(579,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(580,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(581,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(582,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(583,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(584,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(585,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(586,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(587,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(588,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(589,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(590,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(591,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(592,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(593,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(594,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(595,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(596,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(597,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(598,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(599,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(600,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(601,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(602,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(603,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(604,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(605,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(606,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(607,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(608,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(609,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(610,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(611,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(612,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(613,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(614,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(615,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(616,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(617,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(618,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(619,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(620,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(621,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(622,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(623,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(624,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(625,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(626,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(627,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(628,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(629,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(630,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(631,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(632,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(633,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(634,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(635,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(636,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(637,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(638,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(639,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(640,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(641,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(642,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(643,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(644,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(645,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(646,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(647,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(648,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(649,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(650,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(651,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(652,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(653,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(654,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(655,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(656,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(657,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(658,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(659,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(660,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(661,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(662,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(663,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(664,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(665,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(666,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(667,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(668,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(669,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(670,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(671,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(672,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(673,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(674,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(675,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(676,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(677,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(678,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(679,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(680,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(681,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(682,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(683,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(684,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(685,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(686,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(687,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(688,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(689,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(690,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(691,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(692,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(693,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(694,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(695,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(696,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(697,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(698,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(699,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(700,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(701,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(702,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(703,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(704,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(705,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(706,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(707,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(708,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(709,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(710,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(711,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(712,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(713,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(714,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(715,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(716,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(717,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(718,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(719,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(720,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(721,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(722,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(723,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(724,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(725,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(726,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(727,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(728,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(729,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(730,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(731,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(732,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(733,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(734,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(735,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(736,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(737,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(738,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(739,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(740,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(741,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(742,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(743,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(744,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(745,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(746,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(747,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(748,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(749,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(750,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(751,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(752,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(753,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(754,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(755,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(756,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(757,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(758,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(759,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(760,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(761,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(762,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(763,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(764,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(765,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(766,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(767,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(768,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(769,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(770,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(771,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(772,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(773,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(774,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(775,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(776,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(777,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(778,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(779,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(780,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(781,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(782,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(783,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(784,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(785,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(786,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(787,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(788,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(789,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(790,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(791,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(792,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(793,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(794,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(795,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(796,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(797,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(798,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(799,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(800,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(801,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(802,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(803,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(804,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(805,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(806,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(807,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(808,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(809,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(810,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(811,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(812,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(813,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(814,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(815,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(816,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(817,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(818,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(819,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(820,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(821,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(822,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(823,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(824,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(825,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(826,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(827,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(828,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(829,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(830,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(831,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(832,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(833,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(834,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(835,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(836,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(837,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(838,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(839,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(840,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(841,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(842,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(843,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(844,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(845,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(846,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(847,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(848,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(849,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(850,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(851,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(852,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(853,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(854,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(855,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(856,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(857,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(858,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(859,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(860,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(861,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(862,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(863,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(864,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(865,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(866,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(867,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(868,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(869,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(870,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(871,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(872,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(873,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(874,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(875,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(876,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(877,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(878,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(879,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(880,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(881,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(882,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(883,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(884,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(885,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(886,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(887,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(888,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(889,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(890,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(891,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(892,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(893,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(894,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(895,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(896,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(897,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(898,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(899,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(900,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(901,'2026-11-23 18:25:00','Test storage restriction','2026-11-23 18:25:00','PERMIT',2,NULL,'PATH'),(902,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(903,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(904,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(905,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(906,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(907,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(908,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(909,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(910,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(911,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(912,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(913,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(914,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(915,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(916,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(917,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(918,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(919,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(920,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(921,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(922,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(923,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(924,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(925,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(926,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(927,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(928,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(929,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(930,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(931,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(932,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(933,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(934,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(935,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(936,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(937,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(938,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(939,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(940,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(941,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(942,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(943,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(944,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(945,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(946,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(947,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(948,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(949,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(950,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(951,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(952,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(953,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(954,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(955,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(956,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(957,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(958,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(959,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(960,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(961,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(962,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(963,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(964,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(965,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(966,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(967,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(968,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(969,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(970,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(971,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(972,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(973,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(974,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(975,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(976,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(977,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(978,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(979,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(980,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(981,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(982,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(983,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(984,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(985,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(986,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(987,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(988,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(989,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(990,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(991,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(992,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(993,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(994,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(995,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(996,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(997,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(998,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(999,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(1000,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(1001,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(1002,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(1003,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(1004,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH'),(1005,'2026-11-23 18:25:01','Test storage restriction','2026-11-23 18:25:01','PERMIT',2,NULL,'PATH');
/*!40000 ALTER TABLE `iam_scope_policy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_scope_policy_scope`
--

DROP TABLE IF EXISTS `iam_scope_policy_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_scope_policy_scope` (
  `policy_id` bigint DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL,
  UNIQUE KEY `INDEX_iam_scope_policy_scope_policy_id_scope` (`policy_id`,`scope`),
  KEY `INDEX_iam_scope_policy_scope_scope` (`scope`),
  CONSTRAINT `FK_iam_scope_policy_scope_policy_id` FOREIGN KEY (`policy_id`) REFERENCES `iam_scope_policy` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_scope_policy_scope`
--

LOCK TABLES `iam_scope_policy_scope` WRITE;
/*!40000 ALTER TABLE `iam_scope_policy_scope` DISABLE KEYS */;
INSERT INTO `iam_scope_policy_scope` VALUES (2,'storage.create:/'),(2,'storage.modify:/'),(2,'storage.read:/'),(2,'storage.stage:/'),(3,'storage.modify:/$U'),(3,'storage.read:/$U'),(3,'storage.write:/$U'),(4,'storage.modify:/7f24b8c1-b470-437e-9ad9-c9efd6dea111'),(4,'storage.read:/7f24b8c1-b470-437e-9ad9-c9efd6dea111'),(4,'storage.write:/7f24b8c1-b470-437e-9ad9-c9efd6dea111'),(5,'storage.modify:/582d3375-f4f0-47f3-889b-b2f3949adb62'),(5,'storage.read:/582d3375-f4f0-47f3-889b-b2f3949adb62'),(5,'storage.write:/582d3375-f4f0-47f3-889b-b2f3949adb62'),(6,'storage.modify:/7bcd3c6b-8d7d-44f8-8dfa-7d066ba6ff7f'),(6,'storage.read:/7bcd3c6b-8d7d-44f8-8dfa-7d066ba6ff7f'),(6,'storage.write:/7bcd3c6b-8d7d-44f8-8dfa-7d066ba6ff7f'),(7,'storage.modify:/85662b8e-0c42-48ed-8166-b87dc9f6ee10'),(7,'storage.read:/85662b8e-0c42-48ed-8166-b87dc9f6ee10'),(7,'storage.write:/85662b8e-0c42-48ed-8166-b87dc9f6ee10'),(8,'storage.modify:/8b1e5707-9235-4ce5-b551-2b72003dd8cc'),(8,'storage.read:/8b1e5707-9235-4ce5-b551-2b72003dd8cc'),(8,'storage.write:/8b1e5707-9235-4ce5-b551-2b72003dd8cc'),(9,'storage.modify:/ab57d8b6-70b6-4d37-ba51-9e2f67bbbb9e'),(9,'storage.read:/ab57d8b6-70b6-4d37-ba51-9e2f67bbbb9e'),(9,'storage.write:/ab57d8b6-70b6-4d37-ba51-9e2f67bbbb9e'),(10,'storage.modify:/1ff5538b-b8cc-4b7a-999c-89c9727c6f36'),(10,'storage.read:/1ff5538b-b8cc-4b7a-999c-89c9727c6f36'),(10,'storage.write:/1ff5538b-b8cc-4b7a-999c-89c9727c6f36'),(11,'storage.modify:/ed3b4972-36a7-4e23-886f-0b3c270b457a'),(11,'storage.read:/ed3b4972-36a7-4e23-886f-0b3c270b457a'),(11,'storage.write:/ed3b4972-36a7-4e23-886f-0b3c270b457a'),(12,'storage.modify:/90344520-f8da-4fa8-882b-14665ec037ff'),(12,'storage.read:/90344520-f8da-4fa8-882b-14665ec037ff'),(12,'storage.write:/90344520-f8da-4fa8-882b-14665ec037ff'),(13,'storage.modify:/38e389d5-b2c6-4bbb-84d2-78f0e9ecc33c'),(13,'storage.read:/38e389d5-b2c6-4bbb-84d2-78f0e9ecc33c'),(13,'storage.write:/38e389d5-b2c6-4bbb-84d2-78f0e9ecc33c'),(14,'storage.modify:/3b3d14b1-0f52-4ee6-abc7-9c362b7e435c'),(14,'storage.read:/3b3d14b1-0f52-4ee6-abc7-9c362b7e435c'),(14,'storage.write:/3b3d14b1-0f52-4ee6-abc7-9c362b7e435c'),(15,'storage.modify:/4ba442c4-43bd-4a01-985b-a89c3c09c49a'),(15,'storage.read:/4ba442c4-43bd-4a01-985b-a89c3c09c49a'),(15,'storage.write:/4ba442c4-43bd-4a01-985b-a89c3c09c49a'),(16,'storage.modify:/08d48045-e76b-11f1-b5e7-e284dcf81adb'),(16,'storage.read:/08d48045-e76b-11f1-b5e7-e284dcf81adb'),(16,'storage.write:/08d48045-e76b-11f1-b5e7-e284dcf81adb'),(17,'storage.modify:/08d48cac-e76b-11f1-b5e7-e284dcf81adb'),(17,'storage.read:/08d48cac-e76b-11f1-b5e7-e284dcf81adb'),(17,'storage.write:/08d48cac-e76b-11f1-b5e7-e284dcf81adb'),(18,'storage.modify:/08d48fe1-e76b-11f1-b5e7-e284dcf81adb'),(18,'storage.read:/08d48fe1-e76b-11f1-b5e7-e284dcf81adb'),(18,'storage.write:/08d48fe1-e76b-11f1-b5e7-e284dcf81adb'),(19,'storage.modify:/08d49378-e76b-11f1-b5e7-e284dcf81adb'),(19,'storage.read:/08d49378-e76b-11f1-b5e7-e284dcf81adb'),(19,'storage.write:/08d49378-e76b-11f1-b5e7-e284dcf81adb'),(20,'storage.modify:/08d495dd-e76b-11f1-b5e7-e284dcf81adb'),(20,'storage.read:/08d495dd-e76b-11f1-b5e7-e284dcf81adb'),(20,'storage.write:/08d495dd-e76b-11f1-b5e7-e284dcf81adb'),(21,'storage.modify:/08d49837-e76b-11f1-b5e7-e284dcf81adb'),(21,'storage.read:/08d49837-e76b-11f1-b5e7-e284dcf81adb'),(21,'storage.write:/08d49837-e76b-11f1-b5e7-e284dcf81adb'),(22,'storage.modify:/08d49aac-e76b-11f1-b5e7-e284dcf81adb'),(22,'storage.read:/08d49aac-e76b-11f1-b5e7-e284dcf81adb'),(22,'storage.write:/08d49aac-e76b-11f1-b5e7-e284dcf81adb'),(23,'storage.modify:/08d49d02-e76b-11f1-b5e7-e284dcf81adb'),(23,'storage.read:/08d49d02-e76b-11f1-b5e7-e284dcf81adb'),(23,'storage.write:/08d49d02-e76b-11f1-b5e7-e284dcf81adb'),(24,'storage.modify:/08d49f41-e76b-11f1-b5e7-e284dcf81adb'),(24,'storage.read:/08d49f41-e76b-11f1-b5e7-e284dcf81adb'),(24,'storage.write:/08d49f41-e76b-11f1-b5e7-e284dcf81adb'),(25,'storage.modify:/08d4a180-e76b-11f1-b5e7-e284dcf81adb'),(25,'storage.read:/08d4a180-e76b-11f1-b5e7-e284dcf81adb'),(25,'storage.write:/08d4a180-e76b-11f1-b5e7-e284dcf81adb'),(26,'storage.modify:/08d4a3b7-e76b-11f1-b5e7-e284dcf81adb'),(26,'storage.read:/08d4a3b7-e76b-11f1-b5e7-e284dcf81adb'),(26,'storage.write:/08d4a3b7-e76b-11f1-b5e7-e284dcf81adb'),(27,'storage.modify:/08d4a5e7-e76b-11f1-b5e7-e284dcf81adb'),(27,'storage.read:/08d4a5e7-e76b-11f1-b5e7-e284dcf81adb'),(27,'storage.write:/08d4a5e7-e76b-11f1-b5e7-e284dcf81adb'),(28,'storage.modify:/08d4a81b-e76b-11f1-b5e7-e284dcf81adb'),(28,'storage.read:/08d4a81b-e76b-11f1-b5e7-e284dcf81adb'),(28,'storage.write:/08d4a81b-e76b-11f1-b5e7-e284dcf81adb'),(29,'storage.modify:/08d4aa57-e76b-11f1-b5e7-e284dcf81adb'),(29,'storage.read:/08d4aa57-e76b-11f1-b5e7-e284dcf81adb'),(29,'storage.write:/08d4aa57-e76b-11f1-b5e7-e284dcf81adb'),(30,'storage.modify:/08d4acfa-e76b-11f1-b5e7-e284dcf81adb'),(30,'storage.read:/08d4acfa-e76b-11f1-b5e7-e284dcf81adb'),(30,'storage.write:/08d4acfa-e76b-11f1-b5e7-e284dcf81adb'),(31,'storage.modify:/08d4af4b-e76b-11f1-b5e7-e284dcf81adb'),(31,'storage.read:/08d4af4b-e76b-11f1-b5e7-e284dcf81adb'),(31,'storage.write:/08d4af4b-e76b-11f1-b5e7-e284dcf81adb'),(32,'storage.modify:/08d4b199-e76b-11f1-b5e7-e284dcf81adb'),(32,'storage.read:/08d4b199-e76b-11f1-b5e7-e284dcf81adb'),(32,'storage.write:/08d4b199-e76b-11f1-b5e7-e284dcf81adb'),(33,'storage.modify:/08d4b41f-e76b-11f1-b5e7-e284dcf81adb'),(33,'storage.read:/08d4b41f-e76b-11f1-b5e7-e284dcf81adb'),(33,'storage.write:/08d4b41f-e76b-11f1-b5e7-e284dcf81adb'),(34,'storage.modify:/08d4b69c-e76b-11f1-b5e7-e284dcf81adb'),(34,'storage.read:/08d4b69c-e76b-11f1-b5e7-e284dcf81adb'),(34,'storage.write:/08d4b69c-e76b-11f1-b5e7-e284dcf81adb'),(35,'storage.modify:/08d4b8d6-e76b-11f1-b5e7-e284dcf81adb'),(35,'storage.read:/08d4b8d6-e76b-11f1-b5e7-e284dcf81adb'),(35,'storage.write:/08d4b8d6-e76b-11f1-b5e7-e284dcf81adb'),(36,'storage.modify:/08d4bb0b-e76b-11f1-b5e7-e284dcf81adb'),(36,'storage.read:/08d4bb0b-e76b-11f1-b5e7-e284dcf81adb'),(36,'storage.write:/08d4bb0b-e76b-11f1-b5e7-e284dcf81adb'),(37,'storage.modify:/08d4bd4f-e76b-11f1-b5e7-e284dcf81adb'),(37,'storage.read:/08d4bd4f-e76b-11f1-b5e7-e284dcf81adb'),(37,'storage.write:/08d4bd4f-e76b-11f1-b5e7-e284dcf81adb'),(38,'storage.modify:/08d4bf84-e76b-11f1-b5e7-e284dcf81adb'),(38,'storage.read:/08d4bf84-e76b-11f1-b5e7-e284dcf81adb'),(38,'storage.write:/08d4bf84-e76b-11f1-b5e7-e284dcf81adb'),(39,'storage.modify:/08d4c1b5-e76b-11f1-b5e7-e284dcf81adb'),(39,'storage.read:/08d4c1b5-e76b-11f1-b5e7-e284dcf81adb'),(39,'storage.write:/08d4c1b5-e76b-11f1-b5e7-e284dcf81adb'),(40,'storage.modify:/08d4c3fc-e76b-11f1-b5e7-e284dcf81adb'),(40,'storage.read:/08d4c3fc-e76b-11f1-b5e7-e284dcf81adb'),(40,'storage.write:/08d4c3fc-e76b-11f1-b5e7-e284dcf81adb'),(41,'storage.modify:/08d4c644-e76b-11f1-b5e7-e284dcf81adb'),(41,'storage.read:/08d4c644-e76b-11f1-b5e7-e284dcf81adb'),(41,'storage.write:/08d4c644-e76b-11f1-b5e7-e284dcf81adb'),(42,'storage.modify:/08d4c878-e76b-11f1-b5e7-e284dcf81adb'),(42,'storage.read:/08d4c878-e76b-11f1-b5e7-e284dcf81adb'),(42,'storage.write:/08d4c878-e76b-11f1-b5e7-e284dcf81adb'),(43,'storage.modify:/08d4caac-e76b-11f1-b5e7-e284dcf81adb'),(43,'storage.read:/08d4caac-e76b-11f1-b5e7-e284dcf81adb'),(43,'storage.write:/08d4caac-e76b-11f1-b5e7-e284dcf81adb'),(44,'storage.modify:/08d4ccd9-e76b-11f1-b5e7-e284dcf81adb'),(44,'storage.read:/08d4ccd9-e76b-11f1-b5e7-e284dcf81adb'),(44,'storage.write:/08d4ccd9-e76b-11f1-b5e7-e284dcf81adb'),(45,'storage.modify:/08d4cf12-e76b-11f1-b5e7-e284dcf81adb'),(45,'storage.read:/08d4cf12-e76b-11f1-b5e7-e284dcf81adb'),(45,'storage.write:/08d4cf12-e76b-11f1-b5e7-e284dcf81adb'),(46,'storage.modify:/08d4d149-e76b-11f1-b5e7-e284dcf81adb'),(46,'storage.read:/08d4d149-e76b-11f1-b5e7-e284dcf81adb'),(46,'storage.write:/08d4d149-e76b-11f1-b5e7-e284dcf81adb'),(47,'storage.modify:/08d4d404-e76b-11f1-b5e7-e284dcf81adb'),(47,'storage.read:/08d4d404-e76b-11f1-b5e7-e284dcf81adb'),(47,'storage.write:/08d4d404-e76b-11f1-b5e7-e284dcf81adb'),(48,'storage.modify:/08d4d646-e76b-11f1-b5e7-e284dcf81adb'),(48,'storage.read:/08d4d646-e76b-11f1-b5e7-e284dcf81adb'),(48,'storage.write:/08d4d646-e76b-11f1-b5e7-e284dcf81adb'),(49,'storage.modify:/08d4d8e0-e76b-11f1-b5e7-e284dcf81adb'),(49,'storage.read:/08d4d8e0-e76b-11f1-b5e7-e284dcf81adb'),(49,'storage.write:/08d4d8e0-e76b-11f1-b5e7-e284dcf81adb'),(50,'storage.modify:/08d4db2e-e76b-11f1-b5e7-e284dcf81adb'),(50,'storage.read:/08d4db2e-e76b-11f1-b5e7-e284dcf81adb'),(50,'storage.write:/08d4db2e-e76b-11f1-b5e7-e284dcf81adb'),(51,'storage.modify:/08d4dd75-e76b-11f1-b5e7-e284dcf81adb'),(51,'storage.read:/08d4dd75-e76b-11f1-b5e7-e284dcf81adb'),(51,'storage.write:/08d4dd75-e76b-11f1-b5e7-e284dcf81adb'),(52,'storage.modify:/08d4dfb3-e76b-11f1-b5e7-e284dcf81adb'),(52,'storage.read:/08d4dfb3-e76b-11f1-b5e7-e284dcf81adb'),(52,'storage.write:/08d4dfb3-e76b-11f1-b5e7-e284dcf81adb'),(53,'storage.modify:/08d4e1f9-e76b-11f1-b5e7-e284dcf81adb'),(53,'storage.read:/08d4e1f9-e76b-11f1-b5e7-e284dcf81adb'),(53,'storage.write:/08d4e1f9-e76b-11f1-b5e7-e284dcf81adb'),(54,'storage.modify:/08d4e43d-e76b-11f1-b5e7-e284dcf81adb'),(54,'storage.read:/08d4e43d-e76b-11f1-b5e7-e284dcf81adb'),(54,'storage.write:/08d4e43d-e76b-11f1-b5e7-e284dcf81adb'),(55,'storage.modify:/08d4e679-e76b-11f1-b5e7-e284dcf81adb'),(55,'storage.read:/08d4e679-e76b-11f1-b5e7-e284dcf81adb'),(55,'storage.write:/08d4e679-e76b-11f1-b5e7-e284dcf81adb'),(56,'storage.modify:/08d4e8b5-e76b-11f1-b5e7-e284dcf81adb'),(56,'storage.read:/08d4e8b5-e76b-11f1-b5e7-e284dcf81adb'),(56,'storage.write:/08d4e8b5-e76b-11f1-b5e7-e284dcf81adb'),(57,'storage.modify:/08d4eb35-e76b-11f1-b5e7-e284dcf81adb'),(57,'storage.read:/08d4eb35-e76b-11f1-b5e7-e284dcf81adb'),(57,'storage.write:/08d4eb35-e76b-11f1-b5e7-e284dcf81adb'),(58,'storage.modify:/08d4ee4d-e76b-11f1-b5e7-e284dcf81adb'),(58,'storage.read:/08d4ee4d-e76b-11f1-b5e7-e284dcf81adb'),(58,'storage.write:/08d4ee4d-e76b-11f1-b5e7-e284dcf81adb'),(59,'storage.modify:/08d4f0e6-e76b-11f1-b5e7-e284dcf81adb'),(59,'storage.read:/08d4f0e6-e76b-11f1-b5e7-e284dcf81adb'),(59,'storage.write:/08d4f0e6-e76b-11f1-b5e7-e284dcf81adb'),(60,'storage.modify:/08d4f39d-e76b-11f1-b5e7-e284dcf81adb'),(60,'storage.read:/08d4f39d-e76b-11f1-b5e7-e284dcf81adb'),(60,'storage.write:/08d4f39d-e76b-11f1-b5e7-e284dcf81adb'),(61,'storage.modify:/08d4f5fb-e76b-11f1-b5e7-e284dcf81adb'),(61,'storage.read:/08d4f5fb-e76b-11f1-b5e7-e284dcf81adb'),(61,'storage.write:/08d4f5fb-e76b-11f1-b5e7-e284dcf81adb'),(62,'storage.modify:/08d74b67-e76b-11f1-b5e7-e284dcf81adb'),(62,'storage.read:/08d74b67-e76b-11f1-b5e7-e284dcf81adb'),(62,'storage.write:/08d74b67-e76b-11f1-b5e7-e284dcf81adb'),(63,'storage.modify:/08d75120-e76b-11f1-b5e7-e284dcf81adb'),(63,'storage.read:/08d75120-e76b-11f1-b5e7-e284dcf81adb'),(63,'storage.write:/08d75120-e76b-11f1-b5e7-e284dcf81adb'),(64,'storage.modify:/08d75416-e76b-11f1-b5e7-e284dcf81adb'),(64,'storage.read:/08d75416-e76b-11f1-b5e7-e284dcf81adb'),(64,'storage.write:/08d75416-e76b-11f1-b5e7-e284dcf81adb'),(65,'storage.modify:/08d75684-e76b-11f1-b5e7-e284dcf81adb'),(65,'storage.read:/08d75684-e76b-11f1-b5e7-e284dcf81adb'),(65,'storage.write:/08d75684-e76b-11f1-b5e7-e284dcf81adb'),(66,'storage.modify:/08d758cd-e76b-11f1-b5e7-e284dcf81adb'),(66,'storage.read:/08d758cd-e76b-11f1-b5e7-e284dcf81adb'),(66,'storage.write:/08d758cd-e76b-11f1-b5e7-e284dcf81adb'),(67,'storage.modify:/08d75b46-e76b-11f1-b5e7-e284dcf81adb'),(67,'storage.read:/08d75b46-e76b-11f1-b5e7-e284dcf81adb'),(67,'storage.write:/08d75b46-e76b-11f1-b5e7-e284dcf81adb'),(68,'storage.modify:/08d75d8f-e76b-11f1-b5e7-e284dcf81adb'),(68,'storage.read:/08d75d8f-e76b-11f1-b5e7-e284dcf81adb'),(68,'storage.write:/08d75d8f-e76b-11f1-b5e7-e284dcf81adb'),(69,'storage.modify:/08d75fe9-e76b-11f1-b5e7-e284dcf81adb'),(69,'storage.read:/08d75fe9-e76b-11f1-b5e7-e284dcf81adb'),(69,'storage.write:/08d75fe9-e76b-11f1-b5e7-e284dcf81adb'),(70,'storage.modify:/08d76237-e76b-11f1-b5e7-e284dcf81adb'),(70,'storage.read:/08d76237-e76b-11f1-b5e7-e284dcf81adb'),(70,'storage.write:/08d76237-e76b-11f1-b5e7-e284dcf81adb'),(71,'storage.modify:/08d76480-e76b-11f1-b5e7-e284dcf81adb'),(71,'storage.read:/08d76480-e76b-11f1-b5e7-e284dcf81adb'),(71,'storage.write:/08d76480-e76b-11f1-b5e7-e284dcf81adb'),(72,'storage.modify:/08d766c1-e76b-11f1-b5e7-e284dcf81adb'),(72,'storage.read:/08d766c1-e76b-11f1-b5e7-e284dcf81adb'),(72,'storage.write:/08d766c1-e76b-11f1-b5e7-e284dcf81adb'),(73,'storage.modify:/08d7690e-e76b-11f1-b5e7-e284dcf81adb'),(73,'storage.read:/08d7690e-e76b-11f1-b5e7-e284dcf81adb'),(73,'storage.write:/08d7690e-e76b-11f1-b5e7-e284dcf81adb'),(74,'storage.modify:/08d76b9e-e76b-11f1-b5e7-e284dcf81adb'),(74,'storage.read:/08d76b9e-e76b-11f1-b5e7-e284dcf81adb'),(74,'storage.write:/08d76b9e-e76b-11f1-b5e7-e284dcf81adb'),(75,'storage.modify:/08d76de7-e76b-11f1-b5e7-e284dcf81adb'),(75,'storage.read:/08d76de7-e76b-11f1-b5e7-e284dcf81adb'),(75,'storage.write:/08d76de7-e76b-11f1-b5e7-e284dcf81adb'),(76,'storage.modify:/08d77057-e76b-11f1-b5e7-e284dcf81adb'),(76,'storage.read:/08d77057-e76b-11f1-b5e7-e284dcf81adb'),(76,'storage.write:/08d77057-e76b-11f1-b5e7-e284dcf81adb'),(77,'storage.modify:/08d772a7-e76b-11f1-b5e7-e284dcf81adb'),(77,'storage.read:/08d772a7-e76b-11f1-b5e7-e284dcf81adb'),(77,'storage.write:/08d772a7-e76b-11f1-b5e7-e284dcf81adb'),(78,'storage.modify:/08da37b9-e76b-11f1-b5e7-e284dcf81adb'),(78,'storage.read:/08da37b9-e76b-11f1-b5e7-e284dcf81adb'),(78,'storage.write:/08da37b9-e76b-11f1-b5e7-e284dcf81adb'),(79,'storage.modify:/08da3d59-e76b-11f1-b5e7-e284dcf81adb'),(79,'storage.read:/08da3d59-e76b-11f1-b5e7-e284dcf81adb'),(79,'storage.write:/08da3d59-e76b-11f1-b5e7-e284dcf81adb'),(80,'storage.modify:/08da4025-e76b-11f1-b5e7-e284dcf81adb'),(80,'storage.read:/08da4025-e76b-11f1-b5e7-e284dcf81adb'),(80,'storage.write:/08da4025-e76b-11f1-b5e7-e284dcf81adb'),(81,'storage.modify:/08da42ea-e76b-11f1-b5e7-e284dcf81adb'),(81,'storage.read:/08da42ea-e76b-11f1-b5e7-e284dcf81adb'),(81,'storage.write:/08da42ea-e76b-11f1-b5e7-e284dcf81adb'),(82,'storage.modify:/08da4586-e76b-11f1-b5e7-e284dcf81adb'),(82,'storage.read:/08da4586-e76b-11f1-b5e7-e284dcf81adb'),(82,'storage.write:/08da4586-e76b-11f1-b5e7-e284dcf81adb'),(83,'storage.modify:/08da4856-e76b-11f1-b5e7-e284dcf81adb'),(83,'storage.read:/08da4856-e76b-11f1-b5e7-e284dcf81adb'),(83,'storage.write:/08da4856-e76b-11f1-b5e7-e284dcf81adb'),(84,'storage.modify:/08da4ad7-e76b-11f1-b5e7-e284dcf81adb'),(84,'storage.read:/08da4ad7-e76b-11f1-b5e7-e284dcf81adb'),(84,'storage.write:/08da4ad7-e76b-11f1-b5e7-e284dcf81adb'),(85,'storage.modify:/08da4d69-e76b-11f1-b5e7-e284dcf81adb'),(85,'storage.read:/08da4d69-e76b-11f1-b5e7-e284dcf81adb'),(85,'storage.write:/08da4d69-e76b-11f1-b5e7-e284dcf81adb'),(86,'storage.modify:/08da502b-e76b-11f1-b5e7-e284dcf81adb'),(86,'storage.read:/08da502b-e76b-11f1-b5e7-e284dcf81adb'),(86,'storage.write:/08da502b-e76b-11f1-b5e7-e284dcf81adb'),(87,'storage.modify:/08dc976e-e76b-11f1-b5e7-e284dcf81adb'),(87,'storage.read:/08dc976e-e76b-11f1-b5e7-e284dcf81adb'),(87,'storage.write:/08dc976e-e76b-11f1-b5e7-e284dcf81adb'),(88,'storage.modify:/08dc9de5-e76b-11f1-b5e7-e284dcf81adb'),(88,'storage.read:/08dc9de5-e76b-11f1-b5e7-e284dcf81adb'),(88,'storage.write:/08dc9de5-e76b-11f1-b5e7-e284dcf81adb'),(89,'storage.modify:/08dca084-e76b-11f1-b5e7-e284dcf81adb'),(89,'storage.read:/08dca084-e76b-11f1-b5e7-e284dcf81adb'),(89,'storage.write:/08dca084-e76b-11f1-b5e7-e284dcf81adb'),(90,'storage.modify:/08dca2e8-e76b-11f1-b5e7-e284dcf81adb'),(90,'storage.read:/08dca2e8-e76b-11f1-b5e7-e284dcf81adb'),(90,'storage.write:/08dca2e8-e76b-11f1-b5e7-e284dcf81adb'),(91,'storage.modify:/08dca53e-e76b-11f1-b5e7-e284dcf81adb'),(91,'storage.read:/08dca53e-e76b-11f1-b5e7-e284dcf81adb'),(91,'storage.write:/08dca53e-e76b-11f1-b5e7-e284dcf81adb'),(92,'storage.modify:/08de065f-e76b-11f1-b5e7-e284dcf81adb'),(92,'storage.read:/08de065f-e76b-11f1-b5e7-e284dcf81adb'),(92,'storage.write:/08de065f-e76b-11f1-b5e7-e284dcf81adb'),(93,'storage.modify:/08de0b12-e76b-11f1-b5e7-e284dcf81adb'),(93,'storage.read:/08de0b12-e76b-11f1-b5e7-e284dcf81adb'),(93,'storage.write:/08de0b12-e76b-11f1-b5e7-e284dcf81adb'),(94,'storage.modify:/08de0d9e-e76b-11f1-b5e7-e284dcf81adb'),(94,'storage.read:/08de0d9e-e76b-11f1-b5e7-e284dcf81adb'),(94,'storage.write:/08de0d9e-e76b-11f1-b5e7-e284dcf81adb'),(95,'storage.modify:/08de0ff5-e76b-11f1-b5e7-e284dcf81adb'),(95,'storage.read:/08de0ff5-e76b-11f1-b5e7-e284dcf81adb'),(95,'storage.write:/08de0ff5-e76b-11f1-b5e7-e284dcf81adb'),(96,'storage.modify:/08de1247-e76b-11f1-b5e7-e284dcf81adb'),(96,'storage.read:/08de1247-e76b-11f1-b5e7-e284dcf81adb'),(96,'storage.write:/08de1247-e76b-11f1-b5e7-e284dcf81adb'),(97,'storage.modify:/08de149a-e76b-11f1-b5e7-e284dcf81adb'),(97,'storage.read:/08de149a-e76b-11f1-b5e7-e284dcf81adb'),(97,'storage.write:/08de149a-e76b-11f1-b5e7-e284dcf81adb'),(98,'storage.modify:/08de16d4-e76b-11f1-b5e7-e284dcf81adb'),(98,'storage.read:/08de16d4-e76b-11f1-b5e7-e284dcf81adb'),(98,'storage.write:/08de16d4-e76b-11f1-b5e7-e284dcf81adb'),(99,'storage.modify:/08de1917-e76b-11f1-b5e7-e284dcf81adb'),(99,'storage.read:/08de1917-e76b-11f1-b5e7-e284dcf81adb'),(99,'storage.write:/08de1917-e76b-11f1-b5e7-e284dcf81adb'),(100,'storage.modify:/08de1b56-e76b-11f1-b5e7-e284dcf81adb'),(100,'storage.read:/08de1b56-e76b-11f1-b5e7-e284dcf81adb'),(100,'storage.write:/08de1b56-e76b-11f1-b5e7-e284dcf81adb'),(101,'storage.modify:/08de1d99-e76b-11f1-b5e7-e284dcf81adb'),(101,'storage.read:/08de1d99-e76b-11f1-b5e7-e284dcf81adb'),(101,'storage.write:/08de1d99-e76b-11f1-b5e7-e284dcf81adb'),(102,'storage.modify:/08de1fde-e76b-11f1-b5e7-e284dcf81adb'),(102,'storage.read:/08de1fde-e76b-11f1-b5e7-e284dcf81adb'),(102,'storage.write:/08de1fde-e76b-11f1-b5e7-e284dcf81adb'),(103,'storage.modify:/08de22cb-e76b-11f1-b5e7-e284dcf81adb'),(103,'storage.read:/08de22cb-e76b-11f1-b5e7-e284dcf81adb'),(103,'storage.write:/08de22cb-e76b-11f1-b5e7-e284dcf81adb'),(104,'storage.modify:/08de2525-e76b-11f1-b5e7-e284dcf81adb'),(104,'storage.read:/08de2525-e76b-11f1-b5e7-e284dcf81adb'),(104,'storage.write:/08de2525-e76b-11f1-b5e7-e284dcf81adb'),(105,'storage.modify:/08de2773-e76b-11f1-b5e7-e284dcf81adb'),(105,'storage.read:/08de2773-e76b-11f1-b5e7-e284dcf81adb'),(105,'storage.write:/08de2773-e76b-11f1-b5e7-e284dcf81adb'),(106,'storage.modify:/319ab39d-e76b-11f1-b5e7-e284dcf81adb'),(106,'storage.read:/319ab39d-e76b-11f1-b5e7-e284dcf81adb'),(106,'storage.write:/319ab39d-e76b-11f1-b5e7-e284dcf81adb'),(107,'storage.modify:/319abffe-e76b-11f1-b5e7-e284dcf81adb'),(107,'storage.read:/319abffe-e76b-11f1-b5e7-e284dcf81adb'),(107,'storage.write:/319abffe-e76b-11f1-b5e7-e284dcf81adb'),(108,'storage.modify:/319ac322-e76b-11f1-b5e7-e284dcf81adb'),(108,'storage.read:/319ac322-e76b-11f1-b5e7-e284dcf81adb'),(108,'storage.write:/319ac322-e76b-11f1-b5e7-e284dcf81adb'),(109,'storage.modify:/319ac59b-e76b-11f1-b5e7-e284dcf81adb'),(109,'storage.read:/319ac59b-e76b-11f1-b5e7-e284dcf81adb'),(109,'storage.write:/319ac59b-e76b-11f1-b5e7-e284dcf81adb'),(110,'storage.modify:/319ac808-e76b-11f1-b5e7-e284dcf81adb'),(110,'storage.read:/319ac808-e76b-11f1-b5e7-e284dcf81adb'),(110,'storage.write:/319ac808-e76b-11f1-b5e7-e284dcf81adb'),(111,'storage.modify:/319aca79-e76b-11f1-b5e7-e284dcf81adb'),(111,'storage.read:/319aca79-e76b-11f1-b5e7-e284dcf81adb'),(111,'storage.write:/319aca79-e76b-11f1-b5e7-e284dcf81adb'),(112,'storage.modify:/319accd2-e76b-11f1-b5e7-e284dcf81adb'),(112,'storage.read:/319accd2-e76b-11f1-b5e7-e284dcf81adb'),(112,'storage.write:/319accd2-e76b-11f1-b5e7-e284dcf81adb'),(113,'storage.modify:/319acf42-e76b-11f1-b5e7-e284dcf81adb'),(113,'storage.read:/319acf42-e76b-11f1-b5e7-e284dcf81adb'),(113,'storage.write:/319acf42-e76b-11f1-b5e7-e284dcf81adb'),(114,'storage.modify:/319ad19d-e76b-11f1-b5e7-e284dcf81adb'),(114,'storage.read:/319ad19d-e76b-11f1-b5e7-e284dcf81adb'),(114,'storage.write:/319ad19d-e76b-11f1-b5e7-e284dcf81adb'),(115,'storage.modify:/319cd4f1-e76b-11f1-b5e7-e284dcf81adb'),(115,'storage.read:/319cd4f1-e76b-11f1-b5e7-e284dcf81adb'),(115,'storage.write:/319cd4f1-e76b-11f1-b5e7-e284dcf81adb'),(116,'storage.modify:/319cdc49-e76b-11f1-b5e7-e284dcf81adb'),(116,'storage.read:/319cdc49-e76b-11f1-b5e7-e284dcf81adb'),(116,'storage.write:/319cdc49-e76b-11f1-b5e7-e284dcf81adb'),(117,'storage.modify:/319ce0e4-e76b-11f1-b5e7-e284dcf81adb'),(117,'storage.read:/319ce0e4-e76b-11f1-b5e7-e284dcf81adb'),(117,'storage.write:/319ce0e4-e76b-11f1-b5e7-e284dcf81adb'),(118,'storage.modify:/319ce5f9-e76b-11f1-b5e7-e284dcf81adb'),(118,'storage.read:/319ce5f9-e76b-11f1-b5e7-e284dcf81adb'),(118,'storage.write:/319ce5f9-e76b-11f1-b5e7-e284dcf81adb'),(119,'storage.modify:/319cea69-e76b-11f1-b5e7-e284dcf81adb'),(119,'storage.read:/319cea69-e76b-11f1-b5e7-e284dcf81adb'),(119,'storage.write:/319cea69-e76b-11f1-b5e7-e284dcf81adb'),(120,'storage.modify:/319cee88-e76b-11f1-b5e7-e284dcf81adb'),(120,'storage.read:/319cee88-e76b-11f1-b5e7-e284dcf81adb'),(120,'storage.write:/319cee88-e76b-11f1-b5e7-e284dcf81adb'),(121,'storage.modify:/319cf1fa-e76b-11f1-b5e7-e284dcf81adb'),(121,'storage.read:/319cf1fa-e76b-11f1-b5e7-e284dcf81adb'),(121,'storage.write:/319cf1fa-e76b-11f1-b5e7-e284dcf81adb'),(122,'storage.modify:/319cf4a0-e76b-11f1-b5e7-e284dcf81adb'),(122,'storage.read:/319cf4a0-e76b-11f1-b5e7-e284dcf81adb'),(122,'storage.write:/319cf4a0-e76b-11f1-b5e7-e284dcf81adb'),(123,'storage.modify:/319cf76a-e76b-11f1-b5e7-e284dcf81adb'),(123,'storage.read:/319cf76a-e76b-11f1-b5e7-e284dcf81adb'),(123,'storage.write:/319cf76a-e76b-11f1-b5e7-e284dcf81adb'),(124,'storage.modify:/319cf9fe-e76b-11f1-b5e7-e284dcf81adb'),(124,'storage.read:/319cf9fe-e76b-11f1-b5e7-e284dcf81adb'),(124,'storage.write:/319cf9fe-e76b-11f1-b5e7-e284dcf81adb'),(125,'storage.modify:/319cfc84-e76b-11f1-b5e7-e284dcf81adb'),(125,'storage.read:/319cfc84-e76b-11f1-b5e7-e284dcf81adb'),(125,'storage.write:/319cfc84-e76b-11f1-b5e7-e284dcf81adb'),(126,'storage.modify:/319cff0b-e76b-11f1-b5e7-e284dcf81adb'),(126,'storage.read:/319cff0b-e76b-11f1-b5e7-e284dcf81adb'),(126,'storage.write:/319cff0b-e76b-11f1-b5e7-e284dcf81adb'),(127,'storage.modify:/319d0335-e76b-11f1-b5e7-e284dcf81adb'),(127,'storage.read:/319d0335-e76b-11f1-b5e7-e284dcf81adb'),(127,'storage.write:/319d0335-e76b-11f1-b5e7-e284dcf81adb'),(128,'storage.modify:/319d0731-e76b-11f1-b5e7-e284dcf81adb'),(128,'storage.read:/319d0731-e76b-11f1-b5e7-e284dcf81adb'),(128,'storage.write:/319d0731-e76b-11f1-b5e7-e284dcf81adb'),(129,'storage.modify:/319d0be5-e76b-11f1-b5e7-e284dcf81adb'),(129,'storage.read:/319d0be5-e76b-11f1-b5e7-e284dcf81adb'),(129,'storage.write:/319d0be5-e76b-11f1-b5e7-e284dcf81adb'),(130,'storage.modify:/319d0f09-e76b-11f1-b5e7-e284dcf81adb'),(130,'storage.read:/319d0f09-e76b-11f1-b5e7-e284dcf81adb'),(130,'storage.write:/319d0f09-e76b-11f1-b5e7-e284dcf81adb'),(131,'storage.modify:/319d119f-e76b-11f1-b5e7-e284dcf81adb'),(131,'storage.read:/319d119f-e76b-11f1-b5e7-e284dcf81adb'),(131,'storage.write:/319d119f-e76b-11f1-b5e7-e284dcf81adb'),(132,'storage.modify:/319d1434-e76b-11f1-b5e7-e284dcf81adb'),(132,'storage.read:/319d1434-e76b-11f1-b5e7-e284dcf81adb'),(132,'storage.write:/319d1434-e76b-11f1-b5e7-e284dcf81adb'),(133,'storage.modify:/319d16ed-e76b-11f1-b5e7-e284dcf81adb'),(133,'storage.read:/319d16ed-e76b-11f1-b5e7-e284dcf81adb'),(133,'storage.write:/319d16ed-e76b-11f1-b5e7-e284dcf81adb'),(134,'storage.modify:/319d1972-e76b-11f1-b5e7-e284dcf81adb'),(134,'storage.read:/319d1972-e76b-11f1-b5e7-e284dcf81adb'),(134,'storage.write:/319d1972-e76b-11f1-b5e7-e284dcf81adb'),(135,'storage.modify:/319d1c0b-e76b-11f1-b5e7-e284dcf81adb'),(135,'storage.read:/319d1c0b-e76b-11f1-b5e7-e284dcf81adb'),(135,'storage.write:/319d1c0b-e76b-11f1-b5e7-e284dcf81adb'),(136,'storage.modify:/319d1e98-e76b-11f1-b5e7-e284dcf81adb'),(136,'storage.read:/319d1e98-e76b-11f1-b5e7-e284dcf81adb'),(136,'storage.write:/319d1e98-e76b-11f1-b5e7-e284dcf81adb'),(137,'storage.modify:/319d2312-e76b-11f1-b5e7-e284dcf81adb'),(137,'storage.read:/319d2312-e76b-11f1-b5e7-e284dcf81adb'),(137,'storage.write:/319d2312-e76b-11f1-b5e7-e284dcf81adb'),(138,'storage.modify:/319d27c8-e76b-11f1-b5e7-e284dcf81adb'),(138,'storage.read:/319d27c8-e76b-11f1-b5e7-e284dcf81adb'),(138,'storage.write:/319d27c8-e76b-11f1-b5e7-e284dcf81adb'),(139,'storage.modify:/319d2b4e-e76b-11f1-b5e7-e284dcf81adb'),(139,'storage.read:/319d2b4e-e76b-11f1-b5e7-e284dcf81adb'),(139,'storage.write:/319d2b4e-e76b-11f1-b5e7-e284dcf81adb'),(140,'storage.modify:/319d2e67-e76b-11f1-b5e7-e284dcf81adb'),(140,'storage.read:/319d2e67-e76b-11f1-b5e7-e284dcf81adb'),(140,'storage.write:/319d2e67-e76b-11f1-b5e7-e284dcf81adb'),(141,'storage.modify:/319d33df-e76b-11f1-b5e7-e284dcf81adb'),(141,'storage.read:/319d33df-e76b-11f1-b5e7-e284dcf81adb'),(141,'storage.write:/319d33df-e76b-11f1-b5e7-e284dcf81adb'),(142,'storage.modify:/319d3707-e76b-11f1-b5e7-e284dcf81adb'),(142,'storage.read:/319d3707-e76b-11f1-b5e7-e284dcf81adb'),(142,'storage.write:/319d3707-e76b-11f1-b5e7-e284dcf81adb'),(143,'storage.modify:/319d39a2-e76b-11f1-b5e7-e284dcf81adb'),(143,'storage.read:/319d39a2-e76b-11f1-b5e7-e284dcf81adb'),(143,'storage.write:/319d39a2-e76b-11f1-b5e7-e284dcf81adb'),(144,'storage.modify:/319d3c35-e76b-11f1-b5e7-e284dcf81adb'),(144,'storage.read:/319d3c35-e76b-11f1-b5e7-e284dcf81adb'),(144,'storage.write:/319d3c35-e76b-11f1-b5e7-e284dcf81adb'),(145,'storage.modify:/319d3f27-e76b-11f1-b5e7-e284dcf81adb'),(145,'storage.read:/319d3f27-e76b-11f1-b5e7-e284dcf81adb'),(145,'storage.write:/319d3f27-e76b-11f1-b5e7-e284dcf81adb'),(146,'storage.modify:/319d421a-e76b-11f1-b5e7-e284dcf81adb'),(146,'storage.read:/319d421a-e76b-11f1-b5e7-e284dcf81adb'),(146,'storage.write:/319d421a-e76b-11f1-b5e7-e284dcf81adb'),(147,'storage.modify:/319d44e1-e76b-11f1-b5e7-e284dcf81adb'),(147,'storage.read:/319d44e1-e76b-11f1-b5e7-e284dcf81adb'),(147,'storage.write:/319d44e1-e76b-11f1-b5e7-e284dcf81adb'),(148,'storage.modify:/319d47aa-e76b-11f1-b5e7-e284dcf81adb'),(148,'storage.read:/319d47aa-e76b-11f1-b5e7-e284dcf81adb'),(148,'storage.write:/319d47aa-e76b-11f1-b5e7-e284dcf81adb'),(149,'storage.modify:/319d4b9c-e76b-11f1-b5e7-e284dcf81adb'),(149,'storage.read:/319d4b9c-e76b-11f1-b5e7-e284dcf81adb'),(149,'storage.write:/319d4b9c-e76b-11f1-b5e7-e284dcf81adb'),(150,'storage.modify:/319d4fd2-e76b-11f1-b5e7-e284dcf81adb'),(150,'storage.read:/319d4fd2-e76b-11f1-b5e7-e284dcf81adb'),(150,'storage.write:/319d4fd2-e76b-11f1-b5e7-e284dcf81adb'),(151,'storage.modify:/31a0003f-e76b-11f1-b5e7-e284dcf81adb'),(151,'storage.read:/31a0003f-e76b-11f1-b5e7-e284dcf81adb'),(151,'storage.write:/31a0003f-e76b-11f1-b5e7-e284dcf81adb'),(152,'storage.modify:/31a22fb4-e76b-11f1-b5e7-e284dcf81adb'),(152,'storage.read:/31a22fb4-e76b-11f1-b5e7-e284dcf81adb'),(152,'storage.write:/31a22fb4-e76b-11f1-b5e7-e284dcf81adb'),(153,'storage.modify:/31a23524-e76b-11f1-b5e7-e284dcf81adb'),(153,'storage.read:/31a23524-e76b-11f1-b5e7-e284dcf81adb'),(153,'storage.write:/31a23524-e76b-11f1-b5e7-e284dcf81adb'),(154,'storage.modify:/31a238c8-e76b-11f1-b5e7-e284dcf81adb'),(154,'storage.read:/31a238c8-e76b-11f1-b5e7-e284dcf81adb'),(154,'storage.write:/31a238c8-e76b-11f1-b5e7-e284dcf81adb'),(155,'storage.modify:/31a23d7a-e76b-11f1-b5e7-e284dcf81adb'),(155,'storage.read:/31a23d7a-e76b-11f1-b5e7-e284dcf81adb'),(155,'storage.write:/31a23d7a-e76b-11f1-b5e7-e284dcf81adb'),(156,'storage.modify:/31a23fec-e76b-11f1-b5e7-e284dcf81adb'),(156,'storage.read:/31a23fec-e76b-11f1-b5e7-e284dcf81adb'),(156,'storage.write:/31a23fec-e76b-11f1-b5e7-e284dcf81adb'),(157,'storage.modify:/31a241f1-e76b-11f1-b5e7-e284dcf81adb'),(157,'storage.read:/31a241f1-e76b-11f1-b5e7-e284dcf81adb'),(157,'storage.write:/31a241f1-e76b-11f1-b5e7-e284dcf81adb'),(158,'storage.modify:/31a243eb-e76b-11f1-b5e7-e284dcf81adb'),(158,'storage.read:/31a243eb-e76b-11f1-b5e7-e284dcf81adb'),(158,'storage.write:/31a243eb-e76b-11f1-b5e7-e284dcf81adb'),(159,'storage.modify:/31a245e5-e76b-11f1-b5e7-e284dcf81adb'),(159,'storage.read:/31a245e5-e76b-11f1-b5e7-e284dcf81adb'),(159,'storage.write:/31a245e5-e76b-11f1-b5e7-e284dcf81adb'),(160,'storage.modify:/31a247dc-e76b-11f1-b5e7-e284dcf81adb'),(160,'storage.read:/31a247dc-e76b-11f1-b5e7-e284dcf81adb'),(160,'storage.write:/31a247dc-e76b-11f1-b5e7-e284dcf81adb'),(161,'storage.modify:/31a249da-e76b-11f1-b5e7-e284dcf81adb'),(161,'storage.read:/31a249da-e76b-11f1-b5e7-e284dcf81adb'),(161,'storage.write:/31a249da-e76b-11f1-b5e7-e284dcf81adb'),(162,'storage.modify:/31a24bc8-e76b-11f1-b5e7-e284dcf81adb'),(162,'storage.read:/31a24bc8-e76b-11f1-b5e7-e284dcf81adb'),(162,'storage.write:/31a24bc8-e76b-11f1-b5e7-e284dcf81adb'),(163,'storage.modify:/31a24db9-e76b-11f1-b5e7-e284dcf81adb'),(163,'storage.read:/31a24db9-e76b-11f1-b5e7-e284dcf81adb'),(163,'storage.write:/31a24db9-e76b-11f1-b5e7-e284dcf81adb'),(164,'storage.modify:/31a24fa3-e76b-11f1-b5e7-e284dcf81adb'),(164,'storage.read:/31a24fa3-e76b-11f1-b5e7-e284dcf81adb'),(164,'storage.write:/31a24fa3-e76b-11f1-b5e7-e284dcf81adb'),(165,'storage.modify:/31a2518b-e76b-11f1-b5e7-e284dcf81adb'),(165,'storage.read:/31a2518b-e76b-11f1-b5e7-e284dcf81adb'),(165,'storage.write:/31a2518b-e76b-11f1-b5e7-e284dcf81adb'),(166,'storage.modify:/31a25378-e76b-11f1-b5e7-e284dcf81adb'),(166,'storage.read:/31a25378-e76b-11f1-b5e7-e284dcf81adb'),(166,'storage.write:/31a25378-e76b-11f1-b5e7-e284dcf81adb'),(167,'storage.modify:/31a25565-e76b-11f1-b5e7-e284dcf81adb'),(167,'storage.read:/31a25565-e76b-11f1-b5e7-e284dcf81adb'),(167,'storage.write:/31a25565-e76b-11f1-b5e7-e284dcf81adb'),(168,'storage.modify:/31a25751-e76b-11f1-b5e7-e284dcf81adb'),(168,'storage.read:/31a25751-e76b-11f1-b5e7-e284dcf81adb'),(168,'storage.write:/31a25751-e76b-11f1-b5e7-e284dcf81adb'),(169,'storage.modify:/31a2593e-e76b-11f1-b5e7-e284dcf81adb'),(169,'storage.read:/31a2593e-e76b-11f1-b5e7-e284dcf81adb'),(169,'storage.write:/31a2593e-e76b-11f1-b5e7-e284dcf81adb'),(170,'storage.modify:/31a25b24-e76b-11f1-b5e7-e284dcf81adb'),(170,'storage.read:/31a25b24-e76b-11f1-b5e7-e284dcf81adb'),(170,'storage.write:/31a25b24-e76b-11f1-b5e7-e284dcf81adb'),(171,'storage.modify:/31a25d1f-e76b-11f1-b5e7-e284dcf81adb'),(171,'storage.read:/31a25d1f-e76b-11f1-b5e7-e284dcf81adb'),(171,'storage.write:/31a25d1f-e76b-11f1-b5e7-e284dcf81adb'),(172,'storage.modify:/31a25f12-e76b-11f1-b5e7-e284dcf81adb'),(172,'storage.read:/31a25f12-e76b-11f1-b5e7-e284dcf81adb'),(172,'storage.write:/31a25f12-e76b-11f1-b5e7-e284dcf81adb'),(173,'storage.modify:/31a26155-e76b-11f1-b5e7-e284dcf81adb'),(173,'storage.read:/31a26155-e76b-11f1-b5e7-e284dcf81adb'),(173,'storage.write:/31a26155-e76b-11f1-b5e7-e284dcf81adb'),(174,'storage.modify:/31a263aa-e76b-11f1-b5e7-e284dcf81adb'),(174,'storage.read:/31a263aa-e76b-11f1-b5e7-e284dcf81adb'),(174,'storage.write:/31a263aa-e76b-11f1-b5e7-e284dcf81adb'),(175,'storage.modify:/31a265cc-e76b-11f1-b5e7-e284dcf81adb'),(175,'storage.read:/31a265cc-e76b-11f1-b5e7-e284dcf81adb'),(175,'storage.write:/31a265cc-e76b-11f1-b5e7-e284dcf81adb'),(176,'storage.modify:/31a267f2-e76b-11f1-b5e7-e284dcf81adb'),(176,'storage.read:/31a267f2-e76b-11f1-b5e7-e284dcf81adb'),(176,'storage.write:/31a267f2-e76b-11f1-b5e7-e284dcf81adb'),(177,'storage.modify:/31a26dd2-e76b-11f1-b5e7-e284dcf81adb'),(177,'storage.read:/31a26dd2-e76b-11f1-b5e7-e284dcf81adb'),(177,'storage.write:/31a26dd2-e76b-11f1-b5e7-e284dcf81adb'),(178,'storage.modify:/31a270cc-e76b-11f1-b5e7-e284dcf81adb'),(178,'storage.read:/31a270cc-e76b-11f1-b5e7-e284dcf81adb'),(178,'storage.write:/31a270cc-e76b-11f1-b5e7-e284dcf81adb'),(179,'storage.modify:/31a27306-e76b-11f1-b5e7-e284dcf81adb'),(179,'storage.read:/31a27306-e76b-11f1-b5e7-e284dcf81adb'),(179,'storage.write:/31a27306-e76b-11f1-b5e7-e284dcf81adb'),(180,'storage.modify:/31a27537-e76b-11f1-b5e7-e284dcf81adb'),(180,'storage.read:/31a27537-e76b-11f1-b5e7-e284dcf81adb'),(180,'storage.write:/31a27537-e76b-11f1-b5e7-e284dcf81adb'),(181,'storage.modify:/31a27767-e76b-11f1-b5e7-e284dcf81adb'),(181,'storage.read:/31a27767-e76b-11f1-b5e7-e284dcf81adb'),(181,'storage.write:/31a27767-e76b-11f1-b5e7-e284dcf81adb'),(182,'storage.modify:/31a2798b-e76b-11f1-b5e7-e284dcf81adb'),(182,'storage.read:/31a2798b-e76b-11f1-b5e7-e284dcf81adb'),(182,'storage.write:/31a2798b-e76b-11f1-b5e7-e284dcf81adb'),(183,'storage.modify:/31a27bad-e76b-11f1-b5e7-e284dcf81adb'),(183,'storage.read:/31a27bad-e76b-11f1-b5e7-e284dcf81adb'),(183,'storage.write:/31a27bad-e76b-11f1-b5e7-e284dcf81adb'),(184,'storage.modify:/31a27e22-e76b-11f1-b5e7-e284dcf81adb'),(184,'storage.read:/31a27e22-e76b-11f1-b5e7-e284dcf81adb'),(184,'storage.write:/31a27e22-e76b-11f1-b5e7-e284dcf81adb'),(185,'storage.modify:/31a2804c-e76b-11f1-b5e7-e284dcf81adb'),(185,'storage.read:/31a2804c-e76b-11f1-b5e7-e284dcf81adb'),(185,'storage.write:/31a2804c-e76b-11f1-b5e7-e284dcf81adb'),(186,'storage.modify:/31a5549c-e76b-11f1-b5e7-e284dcf81adb'),(186,'storage.read:/31a5549c-e76b-11f1-b5e7-e284dcf81adb'),(186,'storage.write:/31a5549c-e76b-11f1-b5e7-e284dcf81adb'),(187,'storage.modify:/31a557fd-e76b-11f1-b5e7-e284dcf81adb'),(187,'storage.read:/31a557fd-e76b-11f1-b5e7-e284dcf81adb'),(187,'storage.write:/31a557fd-e76b-11f1-b5e7-e284dcf81adb'),(188,'storage.modify:/31a55a5e-e76b-11f1-b5e7-e284dcf81adb'),(188,'storage.read:/31a55a5e-e76b-11f1-b5e7-e284dcf81adb'),(188,'storage.write:/31a55a5e-e76b-11f1-b5e7-e284dcf81adb'),(189,'storage.modify:/31a55cae-e76b-11f1-b5e7-e284dcf81adb'),(189,'storage.read:/31a55cae-e76b-11f1-b5e7-e284dcf81adb'),(189,'storage.write:/31a55cae-e76b-11f1-b5e7-e284dcf81adb'),(190,'storage.modify:/31a55ee6-e76b-11f1-b5e7-e284dcf81adb'),(190,'storage.read:/31a55ee6-e76b-11f1-b5e7-e284dcf81adb'),(190,'storage.write:/31a55ee6-e76b-11f1-b5e7-e284dcf81adb'),(191,'storage.modify:/31a5611d-e76b-11f1-b5e7-e284dcf81adb'),(191,'storage.read:/31a5611d-e76b-11f1-b5e7-e284dcf81adb'),(191,'storage.write:/31a5611d-e76b-11f1-b5e7-e284dcf81adb'),(192,'storage.modify:/31a56347-e76b-11f1-b5e7-e284dcf81adb'),(192,'storage.read:/31a56347-e76b-11f1-b5e7-e284dcf81adb'),(192,'storage.write:/31a56347-e76b-11f1-b5e7-e284dcf81adb'),(193,'storage.modify:/31a56576-e76b-11f1-b5e7-e284dcf81adb'),(193,'storage.read:/31a56576-e76b-11f1-b5e7-e284dcf81adb'),(193,'storage.write:/31a56576-e76b-11f1-b5e7-e284dcf81adb'),(194,'storage.modify:/31a5679a-e76b-11f1-b5e7-e284dcf81adb'),(194,'storage.read:/31a5679a-e76b-11f1-b5e7-e284dcf81adb'),(194,'storage.write:/31a5679a-e76b-11f1-b5e7-e284dcf81adb'),(195,'storage.modify:/31a569cc-e76b-11f1-b5e7-e284dcf81adb'),(195,'storage.read:/31a569cc-e76b-11f1-b5e7-e284dcf81adb'),(195,'storage.write:/31a569cc-e76b-11f1-b5e7-e284dcf81adb'),(196,'storage.modify:/31a56c0d-e76b-11f1-b5e7-e284dcf81adb'),(196,'storage.read:/31a56c0d-e76b-11f1-b5e7-e284dcf81adb'),(196,'storage.write:/31a56c0d-e76b-11f1-b5e7-e284dcf81adb'),(197,'storage.modify:/31a56ebb-e76b-11f1-b5e7-e284dcf81adb'),(197,'storage.read:/31a56ebb-e76b-11f1-b5e7-e284dcf81adb'),(197,'storage.write:/31a56ebb-e76b-11f1-b5e7-e284dcf81adb'),(198,'storage.modify:/31a57101-e76b-11f1-b5e7-e284dcf81adb'),(198,'storage.read:/31a57101-e76b-11f1-b5e7-e284dcf81adb'),(198,'storage.write:/31a57101-e76b-11f1-b5e7-e284dcf81adb'),(199,'storage.modify:/31a57338-e76b-11f1-b5e7-e284dcf81adb'),(199,'storage.read:/31a57338-e76b-11f1-b5e7-e284dcf81adb'),(199,'storage.write:/31a57338-e76b-11f1-b5e7-e284dcf81adb'),(200,'storage.modify:/31a57570-e76b-11f1-b5e7-e284dcf81adb'),(200,'storage.read:/31a57570-e76b-11f1-b5e7-e284dcf81adb'),(200,'storage.write:/31a57570-e76b-11f1-b5e7-e284dcf81adb'),(201,'storage.modify:/31a577a5-e76b-11f1-b5e7-e284dcf81adb'),(201,'storage.read:/31a577a5-e76b-11f1-b5e7-e284dcf81adb'),(201,'storage.write:/31a577a5-e76b-11f1-b5e7-e284dcf81adb'),(202,'storage.modify:/31a579da-e76b-11f1-b5e7-e284dcf81adb'),(202,'storage.read:/31a579da-e76b-11f1-b5e7-e284dcf81adb'),(202,'storage.write:/31a579da-e76b-11f1-b5e7-e284dcf81adb'),(203,'storage.modify:/31a57c0f-e76b-11f1-b5e7-e284dcf81adb'),(203,'storage.read:/31a57c0f-e76b-11f1-b5e7-e284dcf81adb'),(203,'storage.write:/31a57c0f-e76b-11f1-b5e7-e284dcf81adb'),(204,'storage.modify:/31a57e4b-e76b-11f1-b5e7-e284dcf81adb'),(204,'storage.read:/31a57e4b-e76b-11f1-b5e7-e284dcf81adb'),(204,'storage.write:/31a57e4b-e76b-11f1-b5e7-e284dcf81adb'),(205,'storage.modify:/31a5807d-e76b-11f1-b5e7-e284dcf81adb'),(205,'storage.read:/31a5807d-e76b-11f1-b5e7-e284dcf81adb'),(205,'storage.write:/31a5807d-e76b-11f1-b5e7-e284dcf81adb'),(206,'storage.modify:/31a582a8-e76b-11f1-b5e7-e284dcf81adb'),(206,'storage.read:/31a582a8-e76b-11f1-b5e7-e284dcf81adb'),(206,'storage.write:/31a582a8-e76b-11f1-b5e7-e284dcf81adb'),(207,'storage.modify:/31a584e0-e76b-11f1-b5e7-e284dcf81adb'),(207,'storage.read:/31a584e0-e76b-11f1-b5e7-e284dcf81adb'),(207,'storage.write:/31a584e0-e76b-11f1-b5e7-e284dcf81adb'),(208,'storage.modify:/31a58715-e76b-11f1-b5e7-e284dcf81adb'),(208,'storage.read:/31a58715-e76b-11f1-b5e7-e284dcf81adb'),(208,'storage.write:/31a58715-e76b-11f1-b5e7-e284dcf81adb'),(209,'storage.modify:/31a5894d-e76b-11f1-b5e7-e284dcf81adb'),(209,'storage.read:/31a5894d-e76b-11f1-b5e7-e284dcf81adb'),(209,'storage.write:/31a5894d-e76b-11f1-b5e7-e284dcf81adb'),(210,'storage.modify:/31a6df6e-e76b-11f1-b5e7-e284dcf81adb'),(210,'storage.read:/31a6df6e-e76b-11f1-b5e7-e284dcf81adb'),(210,'storage.write:/31a6df6e-e76b-11f1-b5e7-e284dcf81adb'),(211,'storage.modify:/31a6ed1b-e76b-11f1-b5e7-e284dcf81adb'),(211,'storage.read:/31a6ed1b-e76b-11f1-b5e7-e284dcf81adb'),(211,'storage.write:/31a6ed1b-e76b-11f1-b5e7-e284dcf81adb'),(212,'storage.modify:/31a834a0-e76b-11f1-b5e7-e284dcf81adb'),(212,'storage.read:/31a834a0-e76b-11f1-b5e7-e284dcf81adb'),(212,'storage.write:/31a834a0-e76b-11f1-b5e7-e284dcf81adb'),(213,'storage.modify:/31a83998-e76b-11f1-b5e7-e284dcf81adb'),(213,'storage.read:/31a83998-e76b-11f1-b5e7-e284dcf81adb'),(213,'storage.write:/31a83998-e76b-11f1-b5e7-e284dcf81adb'),(214,'storage.modify:/31a83c1e-e76b-11f1-b5e7-e284dcf81adb'),(214,'storage.read:/31a83c1e-e76b-11f1-b5e7-e284dcf81adb'),(214,'storage.write:/31a83c1e-e76b-11f1-b5e7-e284dcf81adb'),(215,'storage.modify:/31a83e81-e76b-11f1-b5e7-e284dcf81adb'),(215,'storage.read:/31a83e81-e76b-11f1-b5e7-e284dcf81adb'),(215,'storage.write:/31a83e81-e76b-11f1-b5e7-e284dcf81adb'),(216,'storage.modify:/31a840cc-e76b-11f1-b5e7-e284dcf81adb'),(216,'storage.read:/31a840cc-e76b-11f1-b5e7-e284dcf81adb'),(216,'storage.write:/31a840cc-e76b-11f1-b5e7-e284dcf81adb'),(217,'storage.modify:/31a84343-e76b-11f1-b5e7-e284dcf81adb'),(217,'storage.read:/31a84343-e76b-11f1-b5e7-e284dcf81adb'),(217,'storage.write:/31a84343-e76b-11f1-b5e7-e284dcf81adb'),(218,'storage.modify:/31a8458e-e76b-11f1-b5e7-e284dcf81adb'),(218,'storage.read:/31a8458e-e76b-11f1-b5e7-e284dcf81adb'),(218,'storage.write:/31a8458e-e76b-11f1-b5e7-e284dcf81adb'),(219,'storage.modify:/31a847cf-e76b-11f1-b5e7-e284dcf81adb'),(219,'storage.read:/31a847cf-e76b-11f1-b5e7-e284dcf81adb'),(219,'storage.write:/31a847cf-e76b-11f1-b5e7-e284dcf81adb'),(220,'storage.modify:/31a84a08-e76b-11f1-b5e7-e284dcf81adb'),(220,'storage.read:/31a84a08-e76b-11f1-b5e7-e284dcf81adb'),(220,'storage.write:/31a84a08-e76b-11f1-b5e7-e284dcf81adb'),(221,'storage.modify:/31a84c41-e76b-11f1-b5e7-e284dcf81adb'),(221,'storage.read:/31a84c41-e76b-11f1-b5e7-e284dcf81adb'),(221,'storage.write:/31a84c41-e76b-11f1-b5e7-e284dcf81adb'),(222,'storage.modify:/31a84fa0-e76b-11f1-b5e7-e284dcf81adb'),(222,'storage.read:/31a84fa0-e76b-11f1-b5e7-e284dcf81adb'),(222,'storage.write:/31a84fa0-e76b-11f1-b5e7-e284dcf81adb'),(223,'storage.modify:/31a85205-e76b-11f1-b5e7-e284dcf81adb'),(223,'storage.read:/31a85205-e76b-11f1-b5e7-e284dcf81adb'),(223,'storage.write:/31a85205-e76b-11f1-b5e7-e284dcf81adb'),(224,'storage.modify:/31a85513-e76b-11f1-b5e7-e284dcf81adb'),(224,'storage.read:/31a85513-e76b-11f1-b5e7-e284dcf81adb'),(224,'storage.write:/31a85513-e76b-11f1-b5e7-e284dcf81adb'),(225,'storage.modify:/31a85799-e76b-11f1-b5e7-e284dcf81adb'),(225,'storage.read:/31a85799-e76b-11f1-b5e7-e284dcf81adb'),(225,'storage.write:/31a85799-e76b-11f1-b5e7-e284dcf81adb'),(226,'storage.modify:/31a859dd-e76b-11f1-b5e7-e284dcf81adb'),(226,'storage.read:/31a859dd-e76b-11f1-b5e7-e284dcf81adb'),(226,'storage.write:/31a859dd-e76b-11f1-b5e7-e284dcf81adb'),(227,'storage.modify:/31aa86af-e76b-11f1-b5e7-e284dcf81adb'),(227,'storage.read:/31aa86af-e76b-11f1-b5e7-e284dcf81adb'),(227,'storage.write:/31aa86af-e76b-11f1-b5e7-e284dcf81adb'),(228,'storage.modify:/31aa8b8e-e76b-11f1-b5e7-e284dcf81adb'),(228,'storage.read:/31aa8b8e-e76b-11f1-b5e7-e284dcf81adb'),(228,'storage.write:/31aa8b8e-e76b-11f1-b5e7-e284dcf81adb'),(229,'storage.modify:/31aa8dde-e76b-11f1-b5e7-e284dcf81adb'),(229,'storage.read:/31aa8dde-e76b-11f1-b5e7-e284dcf81adb'),(229,'storage.write:/31aa8dde-e76b-11f1-b5e7-e284dcf81adb'),(230,'storage.modify:/31aa8ff4-e76b-11f1-b5e7-e284dcf81adb'),(230,'storage.read:/31aa8ff4-e76b-11f1-b5e7-e284dcf81adb'),(230,'storage.write:/31aa8ff4-e76b-11f1-b5e7-e284dcf81adb'),(231,'storage.modify:/31aa920d-e76b-11f1-b5e7-e284dcf81adb'),(231,'storage.read:/31aa920d-e76b-11f1-b5e7-e284dcf81adb'),(231,'storage.write:/31aa920d-e76b-11f1-b5e7-e284dcf81adb'),(232,'storage.modify:/31aa941d-e76b-11f1-b5e7-e284dcf81adb'),(232,'storage.read:/31aa941d-e76b-11f1-b5e7-e284dcf81adb'),(232,'storage.write:/31aa941d-e76b-11f1-b5e7-e284dcf81adb'),(233,'storage.modify:/31aa9628-e76b-11f1-b5e7-e284dcf81adb'),(233,'storage.read:/31aa9628-e76b-11f1-b5e7-e284dcf81adb'),(233,'storage.write:/31aa9628-e76b-11f1-b5e7-e284dcf81adb'),(234,'storage.modify:/31aa982c-e76b-11f1-b5e7-e284dcf81adb'),(234,'storage.read:/31aa982c-e76b-11f1-b5e7-e284dcf81adb'),(234,'storage.write:/31aa982c-e76b-11f1-b5e7-e284dcf81adb'),(235,'storage.modify:/31aa9a4b-e76b-11f1-b5e7-e284dcf81adb'),(235,'storage.read:/31aa9a4b-e76b-11f1-b5e7-e284dcf81adb'),(235,'storage.write:/31aa9a4b-e76b-11f1-b5e7-e284dcf81adb'),(236,'storage.modify:/31aa9cbc-e76b-11f1-b5e7-e284dcf81adb'),(236,'storage.read:/31aa9cbc-e76b-11f1-b5e7-e284dcf81adb'),(236,'storage.write:/31aa9cbc-e76b-11f1-b5e7-e284dcf81adb'),(237,'storage.modify:/31aa9f8d-e76b-11f1-b5e7-e284dcf81adb'),(237,'storage.read:/31aa9f8d-e76b-11f1-b5e7-e284dcf81adb'),(237,'storage.write:/31aa9f8d-e76b-11f1-b5e7-e284dcf81adb'),(238,'storage.modify:/31aaa1da-e76b-11f1-b5e7-e284dcf81adb'),(238,'storage.read:/31aaa1da-e76b-11f1-b5e7-e284dcf81adb'),(238,'storage.write:/31aaa1da-e76b-11f1-b5e7-e284dcf81adb'),(239,'storage.modify:/31aaa419-e76b-11f1-b5e7-e284dcf81adb'),(239,'storage.read:/31aaa419-e76b-11f1-b5e7-e284dcf81adb'),(239,'storage.write:/31aaa419-e76b-11f1-b5e7-e284dcf81adb'),(240,'storage.modify:/31aaa663-e76b-11f1-b5e7-e284dcf81adb'),(240,'storage.read:/31aaa663-e76b-11f1-b5e7-e284dcf81adb'),(240,'storage.write:/31aaa663-e76b-11f1-b5e7-e284dcf81adb'),(241,'storage.modify:/31aaa8a9-e76b-11f1-b5e7-e284dcf81adb'),(241,'storage.read:/31aaa8a9-e76b-11f1-b5e7-e284dcf81adb'),(241,'storage.write:/31aaa8a9-e76b-11f1-b5e7-e284dcf81adb'),(242,'storage.modify:/31aaaae7-e76b-11f1-b5e7-e284dcf81adb'),(242,'storage.read:/31aaaae7-e76b-11f1-b5e7-e284dcf81adb'),(242,'storage.write:/31aaaae7-e76b-11f1-b5e7-e284dcf81adb'),(243,'storage.modify:/31aaad20-e76b-11f1-b5e7-e284dcf81adb'),(243,'storage.read:/31aaad20-e76b-11f1-b5e7-e284dcf81adb'),(243,'storage.write:/31aaad20-e76b-11f1-b5e7-e284dcf81adb'),(244,'storage.modify:/31aaaf65-e76b-11f1-b5e7-e284dcf81adb'),(244,'storage.read:/31aaaf65-e76b-11f1-b5e7-e284dcf81adb'),(244,'storage.write:/31aaaf65-e76b-11f1-b5e7-e284dcf81adb'),(245,'storage.modify:/31aab1a7-e76b-11f1-b5e7-e284dcf81adb'),(245,'storage.read:/31aab1a7-e76b-11f1-b5e7-e284dcf81adb'),(245,'storage.write:/31aab1a7-e76b-11f1-b5e7-e284dcf81adb'),(246,'storage.modify:/31aab3df-e76b-11f1-b5e7-e284dcf81adb'),(246,'storage.read:/31aab3df-e76b-11f1-b5e7-e284dcf81adb'),(246,'storage.write:/31aab3df-e76b-11f1-b5e7-e284dcf81adb'),(247,'storage.modify:/31aab61b-e76b-11f1-b5e7-e284dcf81adb'),(247,'storage.read:/31aab61b-e76b-11f1-b5e7-e284dcf81adb'),(247,'storage.write:/31aab61b-e76b-11f1-b5e7-e284dcf81adb'),(248,'storage.modify:/31aab94c-e76b-11f1-b5e7-e284dcf81adb'),(248,'storage.read:/31aab94c-e76b-11f1-b5e7-e284dcf81adb'),(248,'storage.write:/31aab94c-e76b-11f1-b5e7-e284dcf81adb'),(249,'storage.modify:/31aabbcb-e76b-11f1-b5e7-e284dcf81adb'),(249,'storage.read:/31aabbcb-e76b-11f1-b5e7-e284dcf81adb'),(249,'storage.write:/31aabbcb-e76b-11f1-b5e7-e284dcf81adb'),(250,'storage.modify:/31aabe08-e76b-11f1-b5e7-e284dcf81adb'),(250,'storage.read:/31aabe08-e76b-11f1-b5e7-e284dcf81adb'),(250,'storage.write:/31aabe08-e76b-11f1-b5e7-e284dcf81adb'),(251,'storage.modify:/31aac046-e76b-11f1-b5e7-e284dcf81adb'),(251,'storage.read:/31aac046-e76b-11f1-b5e7-e284dcf81adb'),(251,'storage.write:/31aac046-e76b-11f1-b5e7-e284dcf81adb'),(252,'storage.modify:/31aac287-e76b-11f1-b5e7-e284dcf81adb'),(252,'storage.read:/31aac287-e76b-11f1-b5e7-e284dcf81adb'),(252,'storage.write:/31aac287-e76b-11f1-b5e7-e284dcf81adb'),(253,'storage.modify:/31aac522-e76b-11f1-b5e7-e284dcf81adb'),(253,'storage.read:/31aac522-e76b-11f1-b5e7-e284dcf81adb'),(253,'storage.write:/31aac522-e76b-11f1-b5e7-e284dcf81adb'),(254,'storage.modify:/31aac7b9-e76b-11f1-b5e7-e284dcf81adb'),(254,'storage.read:/31aac7b9-e76b-11f1-b5e7-e284dcf81adb'),(254,'storage.write:/31aac7b9-e76b-11f1-b5e7-e284dcf81adb'),(255,'storage.modify:/31aac9fc-e76b-11f1-b5e7-e284dcf81adb'),(255,'storage.read:/31aac9fc-e76b-11f1-b5e7-e284dcf81adb'),(255,'storage.write:/31aac9fc-e76b-11f1-b5e7-e284dcf81adb'),(256,'storage.modify:/31aacc3a-e76b-11f1-b5e7-e284dcf81adb'),(256,'storage.read:/31aacc3a-e76b-11f1-b5e7-e284dcf81adb'),(256,'storage.write:/31aacc3a-e76b-11f1-b5e7-e284dcf81adb'),(257,'storage.modify:/31aacea0-e76b-11f1-b5e7-e284dcf81adb'),(257,'storage.read:/31aacea0-e76b-11f1-b5e7-e284dcf81adb'),(257,'storage.write:/31aacea0-e76b-11f1-b5e7-e284dcf81adb'),(258,'storage.modify:/31aad0e1-e76b-11f1-b5e7-e284dcf81adb'),(258,'storage.read:/31aad0e1-e76b-11f1-b5e7-e284dcf81adb'),(258,'storage.write:/31aad0e1-e76b-11f1-b5e7-e284dcf81adb'),(259,'storage.modify:/31aad320-e76b-11f1-b5e7-e284dcf81adb'),(259,'storage.read:/31aad320-e76b-11f1-b5e7-e284dcf81adb'),(259,'storage.write:/31aad320-e76b-11f1-b5e7-e284dcf81adb'),(260,'storage.modify:/31aad609-e76b-11f1-b5e7-e284dcf81adb'),(260,'storage.read:/31aad609-e76b-11f1-b5e7-e284dcf81adb'),(260,'storage.write:/31aad609-e76b-11f1-b5e7-e284dcf81adb'),(261,'storage.modify:/31abf266-e76b-11f1-b5e7-e284dcf81adb'),(261,'storage.read:/31abf266-e76b-11f1-b5e7-e284dcf81adb'),(261,'storage.write:/31abf266-e76b-11f1-b5e7-e284dcf81adb'),(262,'storage.modify:/31abf7fa-e76b-11f1-b5e7-e284dcf81adb'),(262,'storage.read:/31abf7fa-e76b-11f1-b5e7-e284dcf81adb'),(262,'storage.write:/31abf7fa-e76b-11f1-b5e7-e284dcf81adb'),(263,'storage.modify:/31abfa92-e76b-11f1-b5e7-e284dcf81adb'),(263,'storage.read:/31abfa92-e76b-11f1-b5e7-e284dcf81adb'),(263,'storage.write:/31abfa92-e76b-11f1-b5e7-e284dcf81adb'),(264,'storage.modify:/31abfd53-e76b-11f1-b5e7-e284dcf81adb'),(264,'storage.read:/31abfd53-e76b-11f1-b5e7-e284dcf81adb'),(264,'storage.write:/31abfd53-e76b-11f1-b5e7-e284dcf81adb'),(265,'storage.modify:/31abfff7-e76b-11f1-b5e7-e284dcf81adb'),(265,'storage.read:/31abfff7-e76b-11f1-b5e7-e284dcf81adb'),(265,'storage.write:/31abfff7-e76b-11f1-b5e7-e284dcf81adb'),(266,'storage.modify:/31ac023c-e76b-11f1-b5e7-e284dcf81adb'),(266,'storage.read:/31ac023c-e76b-11f1-b5e7-e284dcf81adb'),(266,'storage.write:/31ac023c-e76b-11f1-b5e7-e284dcf81adb'),(267,'storage.modify:/31ac0479-e76b-11f1-b5e7-e284dcf81adb'),(267,'storage.read:/31ac0479-e76b-11f1-b5e7-e284dcf81adb'),(267,'storage.write:/31ac0479-e76b-11f1-b5e7-e284dcf81adb'),(268,'storage.modify:/31ac06d4-e76b-11f1-b5e7-e284dcf81adb'),(268,'storage.read:/31ac06d4-e76b-11f1-b5e7-e284dcf81adb'),(268,'storage.write:/31ac06d4-e76b-11f1-b5e7-e284dcf81adb'),(269,'storage.modify:/31ac0916-e76b-11f1-b5e7-e284dcf81adb'),(269,'storage.read:/31ac0916-e76b-11f1-b5e7-e284dcf81adb'),(269,'storage.write:/31ac0916-e76b-11f1-b5e7-e284dcf81adb'),(270,'storage.modify:/31ad6452-e76b-11f1-b5e7-e284dcf81adb'),(270,'storage.read:/31ad6452-e76b-11f1-b5e7-e284dcf81adb'),(270,'storage.write:/31ad6452-e76b-11f1-b5e7-e284dcf81adb'),(271,'storage.modify:/31ad67d4-e76b-11f1-b5e7-e284dcf81adb'),(271,'storage.read:/31ad67d4-e76b-11f1-b5e7-e284dcf81adb'),(271,'storage.write:/31ad67d4-e76b-11f1-b5e7-e284dcf81adb'),(272,'storage.modify:/31ad6a39-e76b-11f1-b5e7-e284dcf81adb'),(272,'storage.read:/31ad6a39-e76b-11f1-b5e7-e284dcf81adb'),(272,'storage.write:/31ad6a39-e76b-11f1-b5e7-e284dcf81adb'),(273,'storage.modify:/31aec89d-e76b-11f1-b5e7-e284dcf81adb'),(273,'storage.read:/31aec89d-e76b-11f1-b5e7-e284dcf81adb'),(273,'storage.write:/31aec89d-e76b-11f1-b5e7-e284dcf81adb'),(274,'storage.modify:/31aecd3b-e76b-11f1-b5e7-e284dcf81adb'),(274,'storage.read:/31aecd3b-e76b-11f1-b5e7-e284dcf81adb'),(274,'storage.write:/31aecd3b-e76b-11f1-b5e7-e284dcf81adb'),(275,'storage.modify:/31b036ee-e76b-11f1-b5e7-e284dcf81adb'),(275,'storage.read:/31b036ee-e76b-11f1-b5e7-e284dcf81adb'),(275,'storage.write:/31b036ee-e76b-11f1-b5e7-e284dcf81adb'),(276,'storage.modify:/31b03b68-e76b-11f1-b5e7-e284dcf81adb'),(276,'storage.read:/31b03b68-e76b-11f1-b5e7-e284dcf81adb'),(276,'storage.write:/31b03b68-e76b-11f1-b5e7-e284dcf81adb'),(277,'storage.modify:/31b03e11-e76b-11f1-b5e7-e284dcf81adb'),(277,'storage.read:/31b03e11-e76b-11f1-b5e7-e284dcf81adb'),(277,'storage.write:/31b03e11-e76b-11f1-b5e7-e284dcf81adb'),(278,'storage.modify:/31b1b279-e76b-11f1-b5e7-e284dcf81adb'),(278,'storage.read:/31b1b279-e76b-11f1-b5e7-e284dcf81adb'),(278,'storage.write:/31b1b279-e76b-11f1-b5e7-e284dcf81adb'),(279,'storage.modify:/31b2728c-e76b-11f1-b5e7-e284dcf81adb'),(279,'storage.read:/31b2728c-e76b-11f1-b5e7-e284dcf81adb'),(279,'storage.write:/31b2728c-e76b-11f1-b5e7-e284dcf81adb'),(280,'storage.modify:/31b275ba-e76b-11f1-b5e7-e284dcf81adb'),(280,'storage.read:/31b275ba-e76b-11f1-b5e7-e284dcf81adb'),(280,'storage.write:/31b275ba-e76b-11f1-b5e7-e284dcf81adb'),(281,'storage.modify:/31b27827-e76b-11f1-b5e7-e284dcf81adb'),(281,'storage.read:/31b27827-e76b-11f1-b5e7-e284dcf81adb'),(281,'storage.write:/31b27827-e76b-11f1-b5e7-e284dcf81adb'),(282,'storage.modify:/31b27a77-e76b-11f1-b5e7-e284dcf81adb'),(282,'storage.read:/31b27a77-e76b-11f1-b5e7-e284dcf81adb'),(282,'storage.write:/31b27a77-e76b-11f1-b5e7-e284dcf81adb'),(283,'storage.modify:/31b27dfb-e76b-11f1-b5e7-e284dcf81adb'),(283,'storage.read:/31b27dfb-e76b-11f1-b5e7-e284dcf81adb'),(283,'storage.write:/31b27dfb-e76b-11f1-b5e7-e284dcf81adb'),(284,'storage.modify:/31b2805f-e76b-11f1-b5e7-e284dcf81adb'),(284,'storage.read:/31b2805f-e76b-11f1-b5e7-e284dcf81adb'),(284,'storage.write:/31b2805f-e76b-11f1-b5e7-e284dcf81adb'),(285,'storage.modify:/31b282b2-e76b-11f1-b5e7-e284dcf81adb'),(285,'storage.read:/31b282b2-e76b-11f1-b5e7-e284dcf81adb'),(285,'storage.write:/31b282b2-e76b-11f1-b5e7-e284dcf81adb'),(286,'storage.modify:/31b2852f-e76b-11f1-b5e7-e284dcf81adb'),(286,'storage.read:/31b2852f-e76b-11f1-b5e7-e284dcf81adb'),(286,'storage.write:/31b2852f-e76b-11f1-b5e7-e284dcf81adb'),(287,'storage.modify:/31b2877e-e76b-11f1-b5e7-e284dcf81adb'),(287,'storage.read:/31b2877e-e76b-11f1-b5e7-e284dcf81adb'),(287,'storage.write:/31b2877e-e76b-11f1-b5e7-e284dcf81adb'),(288,'storage.modify:/31b289bc-e76b-11f1-b5e7-e284dcf81adb'),(288,'storage.read:/31b289bc-e76b-11f1-b5e7-e284dcf81adb'),(288,'storage.write:/31b289bc-e76b-11f1-b5e7-e284dcf81adb'),(289,'storage.modify:/31b28c00-e76b-11f1-b5e7-e284dcf81adb'),(289,'storage.read:/31b28c00-e76b-11f1-b5e7-e284dcf81adb'),(289,'storage.write:/31b28c00-e76b-11f1-b5e7-e284dcf81adb'),(290,'storage.modify:/31b28eae-e76b-11f1-b5e7-e284dcf81adb'),(290,'storage.read:/31b28eae-e76b-11f1-b5e7-e284dcf81adb'),(290,'storage.write:/31b28eae-e76b-11f1-b5e7-e284dcf81adb'),(291,'storage.modify:/31b290fe-e76b-11f1-b5e7-e284dcf81adb'),(291,'storage.read:/31b290fe-e76b-11f1-b5e7-e284dcf81adb'),(291,'storage.write:/31b290fe-e76b-11f1-b5e7-e284dcf81adb'),(292,'storage.modify:/31b29347-e76b-11f1-b5e7-e284dcf81adb'),(292,'storage.read:/31b29347-e76b-11f1-b5e7-e284dcf81adb'),(292,'storage.write:/31b29347-e76b-11f1-b5e7-e284dcf81adb'),(293,'storage.modify:/31b29585-e76b-11f1-b5e7-e284dcf81adb'),(293,'storage.read:/31b29585-e76b-11f1-b5e7-e284dcf81adb'),(293,'storage.write:/31b29585-e76b-11f1-b5e7-e284dcf81adb'),(294,'storage.modify:/31b297c8-e76b-11f1-b5e7-e284dcf81adb'),(294,'storage.read:/31b297c8-e76b-11f1-b5e7-e284dcf81adb'),(294,'storage.write:/31b297c8-e76b-11f1-b5e7-e284dcf81adb'),(295,'storage.modify:/31b29a07-e76b-11f1-b5e7-e284dcf81adb'),(295,'storage.read:/31b29a07-e76b-11f1-b5e7-e284dcf81adb'),(295,'storage.write:/31b29a07-e76b-11f1-b5e7-e284dcf81adb'),(296,'storage.modify:/31b29c47-e76b-11f1-b5e7-e284dcf81adb'),(296,'storage.read:/31b29c47-e76b-11f1-b5e7-e284dcf81adb'),(296,'storage.write:/31b29c47-e76b-11f1-b5e7-e284dcf81adb'),(297,'storage.modify:/31b29e8c-e76b-11f1-b5e7-e284dcf81adb'),(297,'storage.read:/31b29e8c-e76b-11f1-b5e7-e284dcf81adb'),(297,'storage.write:/31b29e8c-e76b-11f1-b5e7-e284dcf81adb'),(298,'storage.modify:/31b2a0cd-e76b-11f1-b5e7-e284dcf81adb'),(298,'storage.read:/31b2a0cd-e76b-11f1-b5e7-e284dcf81adb'),(298,'storage.write:/31b2a0cd-e76b-11f1-b5e7-e284dcf81adb'),(299,'storage.modify:/31b2a30e-e76b-11f1-b5e7-e284dcf81adb'),(299,'storage.read:/31b2a30e-e76b-11f1-b5e7-e284dcf81adb'),(299,'storage.write:/31b2a30e-e76b-11f1-b5e7-e284dcf81adb'),(300,'storage.modify:/31b2a55a-e76b-11f1-b5e7-e284dcf81adb'),(300,'storage.read:/31b2a55a-e76b-11f1-b5e7-e284dcf81adb'),(300,'storage.write:/31b2a55a-e76b-11f1-b5e7-e284dcf81adb'),(301,'storage.modify:/31b2a79b-e76b-11f1-b5e7-e284dcf81adb'),(301,'storage.read:/31b2a79b-e76b-11f1-b5e7-e284dcf81adb'),(301,'storage.write:/31b2a79b-e76b-11f1-b5e7-e284dcf81adb'),(302,'storage.modify:/31b556bd-e76b-11f1-b5e7-e284dcf81adb'),(302,'storage.read:/31b556bd-e76b-11f1-b5e7-e284dcf81adb'),(302,'storage.write:/31b556bd-e76b-11f1-b5e7-e284dcf81adb'),(303,'storage.modify:/31b55bb2-e76b-11f1-b5e7-e284dcf81adb'),(303,'storage.read:/31b55bb2-e76b-11f1-b5e7-e284dcf81adb'),(303,'storage.write:/31b55bb2-e76b-11f1-b5e7-e284dcf81adb'),(304,'storage.modify:/31b55e27-e76b-11f1-b5e7-e284dcf81adb'),(304,'storage.read:/31b55e27-e76b-11f1-b5e7-e284dcf81adb'),(304,'storage.write:/31b55e27-e76b-11f1-b5e7-e284dcf81adb'),(305,'storage.modify:/31b5607a-e76b-11f1-b5e7-e284dcf81adb'),(305,'storage.read:/31b5607a-e76b-11f1-b5e7-e284dcf81adb'),(305,'storage.write:/31b5607a-e76b-11f1-b5e7-e284dcf81adb'),(306,'storage.modify:/31b562b8-e76b-11f1-b5e7-e284dcf81adb'),(306,'storage.read:/31b562b8-e76b-11f1-b5e7-e284dcf81adb'),(306,'storage.write:/31b562b8-e76b-11f1-b5e7-e284dcf81adb'),(307,'storage.modify:/31b564f4-e76b-11f1-b5e7-e284dcf81adb'),(307,'storage.read:/31b564f4-e76b-11f1-b5e7-e284dcf81adb'),(307,'storage.write:/31b564f4-e76b-11f1-b5e7-e284dcf81adb'),(308,'storage.modify:/31b56739-e76b-11f1-b5e7-e284dcf81adb'),(308,'storage.read:/31b56739-e76b-11f1-b5e7-e284dcf81adb'),(308,'storage.write:/31b56739-e76b-11f1-b5e7-e284dcf81adb'),(309,'storage.modify:/31b56979-e76b-11f1-b5e7-e284dcf81adb'),(309,'storage.read:/31b56979-e76b-11f1-b5e7-e284dcf81adb'),(309,'storage.write:/31b56979-e76b-11f1-b5e7-e284dcf81adb'),(310,'storage.modify:/31b62bb2-e76b-11f1-b5e7-e284dcf81adb'),(310,'storage.read:/31b62bb2-e76b-11f1-b5e7-e284dcf81adb'),(310,'storage.write:/31b62bb2-e76b-11f1-b5e7-e284dcf81adb'),(311,'storage.modify:/31b62f60-e76b-11f1-b5e7-e284dcf81adb'),(311,'storage.read:/31b62f60-e76b-11f1-b5e7-e284dcf81adb'),(311,'storage.write:/31b62f60-e76b-11f1-b5e7-e284dcf81adb'),(312,'storage.modify:/31b631e1-e76b-11f1-b5e7-e284dcf81adb'),(312,'storage.read:/31b631e1-e76b-11f1-b5e7-e284dcf81adb'),(312,'storage.write:/31b631e1-e76b-11f1-b5e7-e284dcf81adb'),(313,'storage.modify:/31b634a2-e76b-11f1-b5e7-e284dcf81adb'),(313,'storage.read:/31b634a2-e76b-11f1-b5e7-e284dcf81adb'),(313,'storage.write:/31b634a2-e76b-11f1-b5e7-e284dcf81adb'),(314,'storage.modify:/31b6374e-e76b-11f1-b5e7-e284dcf81adb'),(314,'storage.read:/31b6374e-e76b-11f1-b5e7-e284dcf81adb'),(314,'storage.write:/31b6374e-e76b-11f1-b5e7-e284dcf81adb'),(315,'storage.modify:/31b639c9-e76b-11f1-b5e7-e284dcf81adb'),(315,'storage.read:/31b639c9-e76b-11f1-b5e7-e284dcf81adb'),(315,'storage.write:/31b639c9-e76b-11f1-b5e7-e284dcf81adb'),(316,'storage.modify:/31b63c43-e76b-11f1-b5e7-e284dcf81adb'),(316,'storage.read:/31b63c43-e76b-11f1-b5e7-e284dcf81adb'),(316,'storage.write:/31b63c43-e76b-11f1-b5e7-e284dcf81adb'),(317,'storage.modify:/31b63eb8-e76b-11f1-b5e7-e284dcf81adb'),(317,'storage.read:/31b63eb8-e76b-11f1-b5e7-e284dcf81adb'),(317,'storage.write:/31b63eb8-e76b-11f1-b5e7-e284dcf81adb'),(318,'storage.modify:/31b64126-e76b-11f1-b5e7-e284dcf81adb'),(318,'storage.read:/31b64126-e76b-11f1-b5e7-e284dcf81adb'),(318,'storage.write:/31b64126-e76b-11f1-b5e7-e284dcf81adb'),(319,'storage.modify:/31b6439e-e76b-11f1-b5e7-e284dcf81adb'),(319,'storage.read:/31b6439e-e76b-11f1-b5e7-e284dcf81adb'),(319,'storage.write:/31b6439e-e76b-11f1-b5e7-e284dcf81adb'),(320,'storage.modify:/31b64790-e76b-11f1-b5e7-e284dcf81adb'),(320,'storage.read:/31b64790-e76b-11f1-b5e7-e284dcf81adb'),(320,'storage.write:/31b64790-e76b-11f1-b5e7-e284dcf81adb'),(321,'storage.modify:/31b64a23-e76b-11f1-b5e7-e284dcf81adb'),(321,'storage.read:/31b64a23-e76b-11f1-b5e7-e284dcf81adb'),(321,'storage.write:/31b64a23-e76b-11f1-b5e7-e284dcf81adb'),(322,'storage.modify:/31b64c90-e76b-11f1-b5e7-e284dcf81adb'),(322,'storage.read:/31b64c90-e76b-11f1-b5e7-e284dcf81adb'),(322,'storage.write:/31b64c90-e76b-11f1-b5e7-e284dcf81adb'),(323,'storage.modify:/31b64ef7-e76b-11f1-b5e7-e284dcf81adb'),(323,'storage.read:/31b64ef7-e76b-11f1-b5e7-e284dcf81adb'),(323,'storage.write:/31b64ef7-e76b-11f1-b5e7-e284dcf81adb'),(324,'storage.modify:/31b6515f-e76b-11f1-b5e7-e284dcf81adb'),(324,'storage.read:/31b6515f-e76b-11f1-b5e7-e284dcf81adb'),(324,'storage.write:/31b6515f-e76b-11f1-b5e7-e284dcf81adb'),(325,'storage.modify:/31b653c8-e76b-11f1-b5e7-e284dcf81adb'),(325,'storage.read:/31b653c8-e76b-11f1-b5e7-e284dcf81adb'),(325,'storage.write:/31b653c8-e76b-11f1-b5e7-e284dcf81adb'),(326,'storage.modify:/31b65658-e76b-11f1-b5e7-e284dcf81adb'),(326,'storage.read:/31b65658-e76b-11f1-b5e7-e284dcf81adb'),(326,'storage.write:/31b65658-e76b-11f1-b5e7-e284dcf81adb'),(327,'storage.modify:/31b65892-e76b-11f1-b5e7-e284dcf81adb'),(327,'storage.read:/31b65892-e76b-11f1-b5e7-e284dcf81adb'),(327,'storage.write:/31b65892-e76b-11f1-b5e7-e284dcf81adb'),(328,'storage.modify:/31b65acb-e76b-11f1-b5e7-e284dcf81adb'),(328,'storage.read:/31b65acb-e76b-11f1-b5e7-e284dcf81adb'),(328,'storage.write:/31b65acb-e76b-11f1-b5e7-e284dcf81adb'),(329,'storage.modify:/31b79fed-e76b-11f1-b5e7-e284dcf81adb'),(329,'storage.read:/31b79fed-e76b-11f1-b5e7-e284dcf81adb'),(329,'storage.write:/31b79fed-e76b-11f1-b5e7-e284dcf81adb'),(330,'storage.modify:/31b7a33b-e76b-11f1-b5e7-e284dcf81adb'),(330,'storage.read:/31b7a33b-e76b-11f1-b5e7-e284dcf81adb'),(330,'storage.write:/31b7a33b-e76b-11f1-b5e7-e284dcf81adb'),(331,'storage.modify:/31b7a597-e76b-11f1-b5e7-e284dcf81adb'),(331,'storage.read:/31b7a597-e76b-11f1-b5e7-e284dcf81adb'),(331,'storage.write:/31b7a597-e76b-11f1-b5e7-e284dcf81adb'),(332,'storage.modify:/31b7a7de-e76b-11f1-b5e7-e284dcf81adb'),(332,'storage.read:/31b7a7de-e76b-11f1-b5e7-e284dcf81adb'),(332,'storage.write:/31b7a7de-e76b-11f1-b5e7-e284dcf81adb'),(333,'storage.modify:/31b7aa2f-e76b-11f1-b5e7-e284dcf81adb'),(333,'storage.read:/31b7aa2f-e76b-11f1-b5e7-e284dcf81adb'),(333,'storage.write:/31b7aa2f-e76b-11f1-b5e7-e284dcf81adb'),(334,'storage.modify:/31b7ac6f-e76b-11f1-b5e7-e284dcf81adb'),(334,'storage.read:/31b7ac6f-e76b-11f1-b5e7-e284dcf81adb'),(334,'storage.write:/31b7ac6f-e76b-11f1-b5e7-e284dcf81adb'),(335,'storage.modify:/31b7aebc-e76b-11f1-b5e7-e284dcf81adb'),(335,'storage.read:/31b7aebc-e76b-11f1-b5e7-e284dcf81adb'),(335,'storage.write:/31b7aebc-e76b-11f1-b5e7-e284dcf81adb'),(336,'storage.modify:/31b7b100-e76b-11f1-b5e7-e284dcf81adb'),(336,'storage.read:/31b7b100-e76b-11f1-b5e7-e284dcf81adb'),(336,'storage.write:/31b7b100-e76b-11f1-b5e7-e284dcf81adb'),(337,'storage.modify:/31b7b349-e76b-11f1-b5e7-e284dcf81adb'),(337,'storage.read:/31b7b349-e76b-11f1-b5e7-e284dcf81adb'),(337,'storage.write:/31b7b349-e76b-11f1-b5e7-e284dcf81adb'),(338,'storage.modify:/31b7b587-e76b-11f1-b5e7-e284dcf81adb'),(338,'storage.read:/31b7b587-e76b-11f1-b5e7-e284dcf81adb'),(338,'storage.write:/31b7b587-e76b-11f1-b5e7-e284dcf81adb'),(339,'storage.modify:/31b7b7c6-e76b-11f1-b5e7-e284dcf81adb'),(339,'storage.read:/31b7b7c6-e76b-11f1-b5e7-e284dcf81adb'),(339,'storage.write:/31b7b7c6-e76b-11f1-b5e7-e284dcf81adb'),(340,'storage.modify:/31b7ba08-e76b-11f1-b5e7-e284dcf81adb'),(340,'storage.read:/31b7ba08-e76b-11f1-b5e7-e284dcf81adb'),(340,'storage.write:/31b7ba08-e76b-11f1-b5e7-e284dcf81adb'),(341,'storage.modify:/31b7bc4b-e76b-11f1-b5e7-e284dcf81adb'),(341,'storage.read:/31b7bc4b-e76b-11f1-b5e7-e284dcf81adb'),(341,'storage.write:/31b7bc4b-e76b-11f1-b5e7-e284dcf81adb'),(342,'storage.modify:/31b7bed3-e76b-11f1-b5e7-e284dcf81adb'),(342,'storage.read:/31b7bed3-e76b-11f1-b5e7-e284dcf81adb'),(342,'storage.write:/31b7bed3-e76b-11f1-b5e7-e284dcf81adb'),(343,'storage.modify:/31b7c11b-e76b-11f1-b5e7-e284dcf81adb'),(343,'storage.read:/31b7c11b-e76b-11f1-b5e7-e284dcf81adb'),(343,'storage.write:/31b7c11b-e76b-11f1-b5e7-e284dcf81adb'),(344,'storage.modify:/31b7c35f-e76b-11f1-b5e7-e284dcf81adb'),(344,'storage.read:/31b7c35f-e76b-11f1-b5e7-e284dcf81adb'),(344,'storage.write:/31b7c35f-e76b-11f1-b5e7-e284dcf81adb'),(345,'storage.modify:/31b7c5a4-e76b-11f1-b5e7-e284dcf81adb'),(345,'storage.read:/31b7c5a4-e76b-11f1-b5e7-e284dcf81adb'),(345,'storage.write:/31b7c5a4-e76b-11f1-b5e7-e284dcf81adb'),(346,'storage.modify:/31b7c7e2-e76b-11f1-b5e7-e284dcf81adb'),(346,'storage.read:/31b7c7e2-e76b-11f1-b5e7-e284dcf81adb'),(346,'storage.write:/31b7c7e2-e76b-11f1-b5e7-e284dcf81adb'),(347,'storage.modify:/31b7ca53-e76b-11f1-b5e7-e284dcf81adb'),(347,'storage.read:/31b7ca53-e76b-11f1-b5e7-e284dcf81adb'),(347,'storage.write:/31b7ca53-e76b-11f1-b5e7-e284dcf81adb'),(348,'storage.modify:/31b7cdd4-e76b-11f1-b5e7-e284dcf81adb'),(348,'storage.read:/31b7cdd4-e76b-11f1-b5e7-e284dcf81adb'),(348,'storage.write:/31b7cdd4-e76b-11f1-b5e7-e284dcf81adb'),(349,'storage.modify:/31b7d19a-e76b-11f1-b5e7-e284dcf81adb'),(349,'storage.read:/31b7d19a-e76b-11f1-b5e7-e284dcf81adb'),(349,'storage.write:/31b7d19a-e76b-11f1-b5e7-e284dcf81adb'),(350,'storage.modify:/31b7d493-e76b-11f1-b5e7-e284dcf81adb'),(350,'storage.read:/31b7d493-e76b-11f1-b5e7-e284dcf81adb'),(350,'storage.write:/31b7d493-e76b-11f1-b5e7-e284dcf81adb'),(351,'storage.modify:/31b7d6f1-e76b-11f1-b5e7-e284dcf81adb'),(351,'storage.read:/31b7d6f1-e76b-11f1-b5e7-e284dcf81adb'),(351,'storage.write:/31b7d6f1-e76b-11f1-b5e7-e284dcf81adb'),(352,'storage.modify:/31b7da95-e76b-11f1-b5e7-e284dcf81adb'),(352,'storage.read:/31b7da95-e76b-11f1-b5e7-e284dcf81adb'),(352,'storage.write:/31b7da95-e76b-11f1-b5e7-e284dcf81adb'),(353,'storage.modify:/31b7dcfc-e76b-11f1-b5e7-e284dcf81adb'),(353,'storage.read:/31b7dcfc-e76b-11f1-b5e7-e284dcf81adb'),(353,'storage.write:/31b7dcfc-e76b-11f1-b5e7-e284dcf81adb'),(354,'storage.modify:/31b7df3d-e76b-11f1-b5e7-e284dcf81adb'),(354,'storage.read:/31b7df3d-e76b-11f1-b5e7-e284dcf81adb'),(354,'storage.write:/31b7df3d-e76b-11f1-b5e7-e284dcf81adb'),(355,'storage.modify:/31b7e178-e76b-11f1-b5e7-e284dcf81adb'),(355,'storage.read:/31b7e178-e76b-11f1-b5e7-e284dcf81adb'),(355,'storage.write:/31b7e178-e76b-11f1-b5e7-e284dcf81adb'),(356,'storage.modify:/31b7e3b1-e76b-11f1-b5e7-e284dcf81adb'),(356,'storage.read:/31b7e3b1-e76b-11f1-b5e7-e284dcf81adb'),(356,'storage.write:/31b7e3b1-e76b-11f1-b5e7-e284dcf81adb'),(357,'storage.modify:/31b7e66c-e76b-11f1-b5e7-e284dcf81adb'),(357,'storage.read:/31b7e66c-e76b-11f1-b5e7-e284dcf81adb'),(357,'storage.write:/31b7e66c-e76b-11f1-b5e7-e284dcf81adb'),(358,'storage.modify:/31b7e8b9-e76b-11f1-b5e7-e284dcf81adb'),(358,'storage.read:/31b7e8b9-e76b-11f1-b5e7-e284dcf81adb'),(358,'storage.write:/31b7e8b9-e76b-11f1-b5e7-e284dcf81adb'),(359,'storage.modify:/31b7eaf6-e76b-11f1-b5e7-e284dcf81adb'),(359,'storage.read:/31b7eaf6-e76b-11f1-b5e7-e284dcf81adb'),(359,'storage.write:/31b7eaf6-e76b-11f1-b5e7-e284dcf81adb'),(360,'storage.modify:/31b7ed36-e76b-11f1-b5e7-e284dcf81adb'),(360,'storage.read:/31b7ed36-e76b-11f1-b5e7-e284dcf81adb'),(360,'storage.write:/31b7ed36-e76b-11f1-b5e7-e284dcf81adb'),(361,'storage.modify:/31b7efcb-e76b-11f1-b5e7-e284dcf81adb'),(361,'storage.read:/31b7efcb-e76b-11f1-b5e7-e284dcf81adb'),(361,'storage.write:/31b7efcb-e76b-11f1-b5e7-e284dcf81adb'),(362,'storage.modify:/31b7f22b-e76b-11f1-b5e7-e284dcf81adb'),(362,'storage.read:/31b7f22b-e76b-11f1-b5e7-e284dcf81adb'),(362,'storage.write:/31b7f22b-e76b-11f1-b5e7-e284dcf81adb'),(363,'storage.modify:/31b7f480-e76b-11f1-b5e7-e284dcf81adb'),(363,'storage.read:/31b7f480-e76b-11f1-b5e7-e284dcf81adb'),(363,'storage.write:/31b7f480-e76b-11f1-b5e7-e284dcf81adb'),(364,'storage.modify:/31b7f6c5-e76b-11f1-b5e7-e284dcf81adb'),(364,'storage.read:/31b7f6c5-e76b-11f1-b5e7-e284dcf81adb'),(364,'storage.write:/31b7f6c5-e76b-11f1-b5e7-e284dcf81adb'),(365,'storage.modify:/31b7f904-e76b-11f1-b5e7-e284dcf81adb'),(365,'storage.read:/31b7f904-e76b-11f1-b5e7-e284dcf81adb'),(365,'storage.write:/31b7f904-e76b-11f1-b5e7-e284dcf81adb'),(366,'storage.modify:/31b7fb47-e76b-11f1-b5e7-e284dcf81adb'),(366,'storage.read:/31b7fb47-e76b-11f1-b5e7-e284dcf81adb'),(366,'storage.write:/31b7fb47-e76b-11f1-b5e7-e284dcf81adb'),(367,'storage.modify:/31b7fd8d-e76b-11f1-b5e7-e284dcf81adb'),(367,'storage.read:/31b7fd8d-e76b-11f1-b5e7-e284dcf81adb'),(367,'storage.write:/31b7fd8d-e76b-11f1-b5e7-e284dcf81adb'),(368,'storage.modify:/31b7ffca-e76b-11f1-b5e7-e284dcf81adb'),(368,'storage.read:/31b7ffca-e76b-11f1-b5e7-e284dcf81adb'),(368,'storage.write:/31b7ffca-e76b-11f1-b5e7-e284dcf81adb'),(369,'storage.modify:/31b8020c-e76b-11f1-b5e7-e284dcf81adb'),(369,'storage.read:/31b8020c-e76b-11f1-b5e7-e284dcf81adb'),(369,'storage.write:/31b8020c-e76b-11f1-b5e7-e284dcf81adb'),(370,'storage.modify:/31b8044c-e76b-11f1-b5e7-e284dcf81adb'),(370,'storage.read:/31b8044c-e76b-11f1-b5e7-e284dcf81adb'),(370,'storage.write:/31b8044c-e76b-11f1-b5e7-e284dcf81adb'),(371,'storage.modify:/31b80691-e76b-11f1-b5e7-e284dcf81adb'),(371,'storage.read:/31b80691-e76b-11f1-b5e7-e284dcf81adb'),(371,'storage.write:/31b80691-e76b-11f1-b5e7-e284dcf81adb'),(372,'storage.modify:/31b808d1-e76b-11f1-b5e7-e284dcf81adb'),(372,'storage.read:/31b808d1-e76b-11f1-b5e7-e284dcf81adb'),(372,'storage.write:/31b808d1-e76b-11f1-b5e7-e284dcf81adb'),(373,'storage.modify:/31b80b3b-e76b-11f1-b5e7-e284dcf81adb'),(373,'storage.read:/31b80b3b-e76b-11f1-b5e7-e284dcf81adb'),(373,'storage.write:/31b80b3b-e76b-11f1-b5e7-e284dcf81adb'),(374,'storage.modify:/31b80d87-e76b-11f1-b5e7-e284dcf81adb'),(374,'storage.read:/31b80d87-e76b-11f1-b5e7-e284dcf81adb'),(374,'storage.write:/31b80d87-e76b-11f1-b5e7-e284dcf81adb'),(375,'storage.modify:/31b80fdc-e76b-11f1-b5e7-e284dcf81adb'),(375,'storage.read:/31b80fdc-e76b-11f1-b5e7-e284dcf81adb'),(375,'storage.write:/31b80fdc-e76b-11f1-b5e7-e284dcf81adb'),(376,'storage.modify:/31b81228-e76b-11f1-b5e7-e284dcf81adb'),(376,'storage.read:/31b81228-e76b-11f1-b5e7-e284dcf81adb'),(376,'storage.write:/31b81228-e76b-11f1-b5e7-e284dcf81adb'),(377,'storage.modify:/31ba7713-e76b-11f1-b5e7-e284dcf81adb'),(377,'storage.read:/31ba7713-e76b-11f1-b5e7-e284dcf81adb'),(377,'storage.write:/31ba7713-e76b-11f1-b5e7-e284dcf81adb'),(378,'storage.modify:/31ba7d37-e76b-11f1-b5e7-e284dcf81adb'),(378,'storage.read:/31ba7d37-e76b-11f1-b5e7-e284dcf81adb'),(378,'storage.write:/31ba7d37-e76b-11f1-b5e7-e284dcf81adb'),(379,'storage.modify:/31ba7ff6-e76b-11f1-b5e7-e284dcf81adb'),(379,'storage.read:/31ba7ff6-e76b-11f1-b5e7-e284dcf81adb'),(379,'storage.write:/31ba7ff6-e76b-11f1-b5e7-e284dcf81adb'),(380,'storage.modify:/31ba8255-e76b-11f1-b5e7-e284dcf81adb'),(380,'storage.read:/31ba8255-e76b-11f1-b5e7-e284dcf81adb'),(380,'storage.write:/31ba8255-e76b-11f1-b5e7-e284dcf81adb'),(381,'storage.modify:/31ba84ae-e76b-11f1-b5e7-e284dcf81adb'),(381,'storage.read:/31ba84ae-e76b-11f1-b5e7-e284dcf81adb'),(381,'storage.write:/31ba84ae-e76b-11f1-b5e7-e284dcf81adb'),(382,'storage.modify:/31ba8704-e76b-11f1-b5e7-e284dcf81adb'),(382,'storage.read:/31ba8704-e76b-11f1-b5e7-e284dcf81adb'),(382,'storage.write:/31ba8704-e76b-11f1-b5e7-e284dcf81adb'),(383,'storage.modify:/31ba894b-e76b-11f1-b5e7-e284dcf81adb'),(383,'storage.read:/31ba894b-e76b-11f1-b5e7-e284dcf81adb'),(383,'storage.write:/31ba894b-e76b-11f1-b5e7-e284dcf81adb'),(384,'storage.modify:/31ba8b93-e76b-11f1-b5e7-e284dcf81adb'),(384,'storage.read:/31ba8b93-e76b-11f1-b5e7-e284dcf81adb'),(384,'storage.write:/31ba8b93-e76b-11f1-b5e7-e284dcf81adb'),(385,'storage.modify:/31ba8de0-e76b-11f1-b5e7-e284dcf81adb'),(385,'storage.read:/31ba8de0-e76b-11f1-b5e7-e284dcf81adb'),(385,'storage.write:/31ba8de0-e76b-11f1-b5e7-e284dcf81adb'),(386,'storage.modify:/31ba902d-e76b-11f1-b5e7-e284dcf81adb'),(386,'storage.read:/31ba902d-e76b-11f1-b5e7-e284dcf81adb'),(386,'storage.write:/31ba902d-e76b-11f1-b5e7-e284dcf81adb'),(387,'storage.modify:/31ba9276-e76b-11f1-b5e7-e284dcf81adb'),(387,'storage.read:/31ba9276-e76b-11f1-b5e7-e284dcf81adb'),(387,'storage.write:/31ba9276-e76b-11f1-b5e7-e284dcf81adb'),(388,'storage.modify:/31bb5630-e76b-11f1-b5e7-e284dcf81adb'),(388,'storage.read:/31bb5630-e76b-11f1-b5e7-e284dcf81adb'),(388,'storage.write:/31bb5630-e76b-11f1-b5e7-e284dcf81adb'),(389,'storage.modify:/31bb5b1b-e76b-11f1-b5e7-e284dcf81adb'),(389,'storage.read:/31bb5b1b-e76b-11f1-b5e7-e284dcf81adb'),(389,'storage.write:/31bb5b1b-e76b-11f1-b5e7-e284dcf81adb'),(390,'storage.modify:/31bb5dd2-e76b-11f1-b5e7-e284dcf81adb'),(390,'storage.read:/31bb5dd2-e76b-11f1-b5e7-e284dcf81adb'),(390,'storage.write:/31bb5dd2-e76b-11f1-b5e7-e284dcf81adb'),(391,'storage.modify:/31bb619a-e76b-11f1-b5e7-e284dcf81adb'),(391,'storage.read:/31bb619a-e76b-11f1-b5e7-e284dcf81adb'),(391,'storage.write:/31bb619a-e76b-11f1-b5e7-e284dcf81adb'),(392,'storage.modify:/31bb6404-e76b-11f1-b5e7-e284dcf81adb'),(392,'storage.read:/31bb6404-e76b-11f1-b5e7-e284dcf81adb'),(392,'storage.write:/31bb6404-e76b-11f1-b5e7-e284dcf81adb'),(393,'storage.modify:/31bb66b5-e76b-11f1-b5e7-e284dcf81adb'),(393,'storage.read:/31bb66b5-e76b-11f1-b5e7-e284dcf81adb'),(393,'storage.write:/31bb66b5-e76b-11f1-b5e7-e284dcf81adb'),(394,'storage.modify:/31bb6946-e76b-11f1-b5e7-e284dcf81adb'),(394,'storage.read:/31bb6946-e76b-11f1-b5e7-e284dcf81adb'),(394,'storage.write:/31bb6946-e76b-11f1-b5e7-e284dcf81adb'),(395,'storage.modify:/31bb6b92-e76b-11f1-b5e7-e284dcf81adb'),(395,'storage.read:/31bb6b92-e76b-11f1-b5e7-e284dcf81adb'),(395,'storage.write:/31bb6b92-e76b-11f1-b5e7-e284dcf81adb'),(396,'storage.modify:/31bb6de2-e76b-11f1-b5e7-e284dcf81adb'),(396,'storage.read:/31bb6de2-e76b-11f1-b5e7-e284dcf81adb'),(396,'storage.write:/31bb6de2-e76b-11f1-b5e7-e284dcf81adb'),(397,'storage.modify:/31bb7046-e76b-11f1-b5e7-e284dcf81adb'),(397,'storage.read:/31bb7046-e76b-11f1-b5e7-e284dcf81adb'),(397,'storage.write:/31bb7046-e76b-11f1-b5e7-e284dcf81adb'),(398,'storage.modify:/31bb7295-e76b-11f1-b5e7-e284dcf81adb'),(398,'storage.read:/31bb7295-e76b-11f1-b5e7-e284dcf81adb'),(398,'storage.write:/31bb7295-e76b-11f1-b5e7-e284dcf81adb'),(399,'storage.modify:/31bb74e2-e76b-11f1-b5e7-e284dcf81adb'),(399,'storage.read:/31bb74e2-e76b-11f1-b5e7-e284dcf81adb'),(399,'storage.write:/31bb74e2-e76b-11f1-b5e7-e284dcf81adb'),(400,'storage.modify:/31bb772c-e76b-11f1-b5e7-e284dcf81adb'),(400,'storage.read:/31bb772c-e76b-11f1-b5e7-e284dcf81adb'),(400,'storage.write:/31bb772c-e76b-11f1-b5e7-e284dcf81adb'),(401,'storage.modify:/31bb7980-e76b-11f1-b5e7-e284dcf81adb'),(401,'storage.read:/31bb7980-e76b-11f1-b5e7-e284dcf81adb'),(401,'storage.write:/31bb7980-e76b-11f1-b5e7-e284dcf81adb'),(402,'storage.modify:/31bb7bc7-e76b-11f1-b5e7-e284dcf81adb'),(402,'storage.read:/31bb7bc7-e76b-11f1-b5e7-e284dcf81adb'),(402,'storage.write:/31bb7bc7-e76b-11f1-b5e7-e284dcf81adb'),(403,'storage.modify:/31bb7e11-e76b-11f1-b5e7-e284dcf81adb'),(403,'storage.read:/31bb7e11-e76b-11f1-b5e7-e284dcf81adb'),(403,'storage.write:/31bb7e11-e76b-11f1-b5e7-e284dcf81adb'),(404,'storage.modify:/31bb805b-e76b-11f1-b5e7-e284dcf81adb'),(404,'storage.read:/31bb805b-e76b-11f1-b5e7-e284dcf81adb'),(404,'storage.write:/31bb805b-e76b-11f1-b5e7-e284dcf81adb'),(405,'storage.modify:/31bb82a0-e76b-11f1-b5e7-e284dcf81adb'),(405,'storage.read:/31bb82a0-e76b-11f1-b5e7-e284dcf81adb'),(405,'storage.write:/31bb82a0-e76b-11f1-b5e7-e284dcf81adb'),(406,'storage.modify:/31bb84e1-e76b-11f1-b5e7-e284dcf81adb'),(406,'storage.read:/31bb84e1-e76b-11f1-b5e7-e284dcf81adb'),(406,'storage.write:/31bb84e1-e76b-11f1-b5e7-e284dcf81adb'),(407,'storage.modify:/31bb8725-e76b-11f1-b5e7-e284dcf81adb'),(407,'storage.read:/31bb8725-e76b-11f1-b5e7-e284dcf81adb'),(407,'storage.write:/31bb8725-e76b-11f1-b5e7-e284dcf81adb'),(408,'storage.modify:/31bb8984-e76b-11f1-b5e7-e284dcf81adb'),(408,'storage.read:/31bb8984-e76b-11f1-b5e7-e284dcf81adb'),(408,'storage.write:/31bb8984-e76b-11f1-b5e7-e284dcf81adb'),(409,'storage.modify:/31bb8bd2-e76b-11f1-b5e7-e284dcf81adb'),(409,'storage.read:/31bb8bd2-e76b-11f1-b5e7-e284dcf81adb'),(409,'storage.write:/31bb8bd2-e76b-11f1-b5e7-e284dcf81adb'),(410,'storage.modify:/31bb8e77-e76b-11f1-b5e7-e284dcf81adb'),(410,'storage.read:/31bb8e77-e76b-11f1-b5e7-e284dcf81adb'),(410,'storage.write:/31bb8e77-e76b-11f1-b5e7-e284dcf81adb'),(411,'storage.modify:/31bb90ca-e76b-11f1-b5e7-e284dcf81adb'),(411,'storage.read:/31bb90ca-e76b-11f1-b5e7-e284dcf81adb'),(411,'storage.write:/31bb90ca-e76b-11f1-b5e7-e284dcf81adb'),(412,'storage.modify:/31bb9329-e76b-11f1-b5e7-e284dcf81adb'),(412,'storage.read:/31bb9329-e76b-11f1-b5e7-e284dcf81adb'),(412,'storage.write:/31bb9329-e76b-11f1-b5e7-e284dcf81adb'),(413,'storage.modify:/31bb9530-e76b-11f1-b5e7-e284dcf81adb'),(413,'storage.read:/31bb9530-e76b-11f1-b5e7-e284dcf81adb'),(413,'storage.write:/31bb9530-e76b-11f1-b5e7-e284dcf81adb'),(414,'storage.modify:/31bb9742-e76b-11f1-b5e7-e284dcf81adb'),(414,'storage.read:/31bb9742-e76b-11f1-b5e7-e284dcf81adb'),(414,'storage.write:/31bb9742-e76b-11f1-b5e7-e284dcf81adb'),(415,'storage.modify:/31bb994d-e76b-11f1-b5e7-e284dcf81adb'),(415,'storage.read:/31bb994d-e76b-11f1-b5e7-e284dcf81adb'),(415,'storage.write:/31bb994d-e76b-11f1-b5e7-e284dcf81adb'),(416,'storage.modify:/31bb9b5f-e76b-11f1-b5e7-e284dcf81adb'),(416,'storage.read:/31bb9b5f-e76b-11f1-b5e7-e284dcf81adb'),(416,'storage.write:/31bb9b5f-e76b-11f1-b5e7-e284dcf81adb'),(417,'storage.modify:/31bb9d6c-e76b-11f1-b5e7-e284dcf81adb'),(417,'storage.read:/31bb9d6c-e76b-11f1-b5e7-e284dcf81adb'),(417,'storage.write:/31bb9d6c-e76b-11f1-b5e7-e284dcf81adb'),(418,'storage.modify:/31bb9f77-e76b-11f1-b5e7-e284dcf81adb'),(418,'storage.read:/31bb9f77-e76b-11f1-b5e7-e284dcf81adb'),(418,'storage.write:/31bb9f77-e76b-11f1-b5e7-e284dcf81adb'),(419,'storage.modify:/31bba176-e76b-11f1-b5e7-e284dcf81adb'),(419,'storage.read:/31bba176-e76b-11f1-b5e7-e284dcf81adb'),(419,'storage.write:/31bba176-e76b-11f1-b5e7-e284dcf81adb'),(420,'storage.modify:/31bba385-e76b-11f1-b5e7-e284dcf81adb'),(420,'storage.read:/31bba385-e76b-11f1-b5e7-e284dcf81adb'),(420,'storage.write:/31bba385-e76b-11f1-b5e7-e284dcf81adb'),(421,'storage.modify:/31bba6a6-e76b-11f1-b5e7-e284dcf81adb'),(421,'storage.read:/31bba6a6-e76b-11f1-b5e7-e284dcf81adb'),(421,'storage.write:/31bba6a6-e76b-11f1-b5e7-e284dcf81adb'),(422,'storage.modify:/31bba95d-e76b-11f1-b5e7-e284dcf81adb'),(422,'storage.read:/31bba95d-e76b-11f1-b5e7-e284dcf81adb'),(422,'storage.write:/31bba95d-e76b-11f1-b5e7-e284dcf81adb'),(423,'storage.modify:/31bbabb5-e76b-11f1-b5e7-e284dcf81adb'),(423,'storage.read:/31bbabb5-e76b-11f1-b5e7-e284dcf81adb'),(423,'storage.write:/31bbabb5-e76b-11f1-b5e7-e284dcf81adb'),(424,'storage.modify:/31bbadfd-e76b-11f1-b5e7-e284dcf81adb'),(424,'storage.read:/31bbadfd-e76b-11f1-b5e7-e284dcf81adb'),(424,'storage.write:/31bbadfd-e76b-11f1-b5e7-e284dcf81adb'),(425,'storage.modify:/31bbb04f-e76b-11f1-b5e7-e284dcf81adb'),(425,'storage.read:/31bbb04f-e76b-11f1-b5e7-e284dcf81adb'),(425,'storage.write:/31bbb04f-e76b-11f1-b5e7-e284dcf81adb'),(426,'storage.modify:/31bbb28d-e76b-11f1-b5e7-e284dcf81adb'),(426,'storage.read:/31bbb28d-e76b-11f1-b5e7-e284dcf81adb'),(426,'storage.write:/31bbb28d-e76b-11f1-b5e7-e284dcf81adb'),(427,'storage.modify:/31bbb529-e76b-11f1-b5e7-e284dcf81adb'),(427,'storage.read:/31bbb529-e76b-11f1-b5e7-e284dcf81adb'),(427,'storage.write:/31bbb529-e76b-11f1-b5e7-e284dcf81adb'),(428,'storage.modify:/31bbb78e-e76b-11f1-b5e7-e284dcf81adb'),(428,'storage.read:/31bbb78e-e76b-11f1-b5e7-e284dcf81adb'),(428,'storage.write:/31bbb78e-e76b-11f1-b5e7-e284dcf81adb'),(429,'storage.modify:/31bbb9d0-e76b-11f1-b5e7-e284dcf81adb'),(429,'storage.read:/31bbb9d0-e76b-11f1-b5e7-e284dcf81adb'),(429,'storage.write:/31bbb9d0-e76b-11f1-b5e7-e284dcf81adb'),(430,'storage.modify:/31bbbc0f-e76b-11f1-b5e7-e284dcf81adb'),(430,'storage.read:/31bbbc0f-e76b-11f1-b5e7-e284dcf81adb'),(430,'storage.write:/31bbbc0f-e76b-11f1-b5e7-e284dcf81adb'),(431,'storage.modify:/31bbbe4b-e76b-11f1-b5e7-e284dcf81adb'),(431,'storage.read:/31bbbe4b-e76b-11f1-b5e7-e284dcf81adb'),(431,'storage.write:/31bbbe4b-e76b-11f1-b5e7-e284dcf81adb'),(432,'storage.modify:/31bbc091-e76b-11f1-b5e7-e284dcf81adb'),(432,'storage.read:/31bbc091-e76b-11f1-b5e7-e284dcf81adb'),(432,'storage.write:/31bbc091-e76b-11f1-b5e7-e284dcf81adb'),(433,'storage.modify:/31bbc2dd-e76b-11f1-b5e7-e284dcf81adb'),(433,'storage.read:/31bbc2dd-e76b-11f1-b5e7-e284dcf81adb'),(433,'storage.write:/31bbc2dd-e76b-11f1-b5e7-e284dcf81adb'),(434,'storage.modify:/31bbc523-e76b-11f1-b5e7-e284dcf81adb'),(434,'storage.read:/31bbc523-e76b-11f1-b5e7-e284dcf81adb'),(434,'storage.write:/31bbc523-e76b-11f1-b5e7-e284dcf81adb'),(435,'storage.modify:/31bbc768-e76b-11f1-b5e7-e284dcf81adb'),(435,'storage.read:/31bbc768-e76b-11f1-b5e7-e284dcf81adb'),(435,'storage.write:/31bbc768-e76b-11f1-b5e7-e284dcf81adb'),(436,'storage.modify:/31bbc9aa-e76b-11f1-b5e7-e284dcf81adb'),(436,'storage.read:/31bbc9aa-e76b-11f1-b5e7-e284dcf81adb'),(436,'storage.write:/31bbc9aa-e76b-11f1-b5e7-e284dcf81adb'),(437,'storage.modify:/31bbcbf1-e76b-11f1-b5e7-e284dcf81adb'),(437,'storage.read:/31bbcbf1-e76b-11f1-b5e7-e284dcf81adb'),(437,'storage.write:/31bbcbf1-e76b-11f1-b5e7-e284dcf81adb'),(438,'storage.modify:/31bbce37-e76b-11f1-b5e7-e284dcf81adb'),(438,'storage.read:/31bbce37-e76b-11f1-b5e7-e284dcf81adb'),(438,'storage.write:/31bbce37-e76b-11f1-b5e7-e284dcf81adb'),(439,'storage.modify:/31bbd076-e76b-11f1-b5e7-e284dcf81adb'),(439,'storage.read:/31bbd076-e76b-11f1-b5e7-e284dcf81adb'),(439,'storage.write:/31bbd076-e76b-11f1-b5e7-e284dcf81adb'),(440,'storage.modify:/31bbd2b6-e76b-11f1-b5e7-e284dcf81adb'),(440,'storage.read:/31bbd2b6-e76b-11f1-b5e7-e284dcf81adb'),(440,'storage.write:/31bbd2b6-e76b-11f1-b5e7-e284dcf81adb'),(441,'storage.modify:/31bbd4fd-e76b-11f1-b5e7-e284dcf81adb'),(441,'storage.read:/31bbd4fd-e76b-11f1-b5e7-e284dcf81adb'),(441,'storage.write:/31bbd4fd-e76b-11f1-b5e7-e284dcf81adb'),(442,'storage.modify:/31bbd74b-e76b-11f1-b5e7-e284dcf81adb'),(442,'storage.read:/31bbd74b-e76b-11f1-b5e7-e284dcf81adb'),(442,'storage.write:/31bbd74b-e76b-11f1-b5e7-e284dcf81adb'),(443,'storage.modify:/31bbd99b-e76b-11f1-b5e7-e284dcf81adb'),(443,'storage.read:/31bbd99b-e76b-11f1-b5e7-e284dcf81adb'),(443,'storage.write:/31bbd99b-e76b-11f1-b5e7-e284dcf81adb'),(444,'storage.modify:/31bbdc16-e76b-11f1-b5e7-e284dcf81adb'),(444,'storage.read:/31bbdc16-e76b-11f1-b5e7-e284dcf81adb'),(444,'storage.write:/31bbdc16-e76b-11f1-b5e7-e284dcf81adb'),(445,'storage.modify:/31bbde68-e76b-11f1-b5e7-e284dcf81adb'),(445,'storage.read:/31bbde68-e76b-11f1-b5e7-e284dcf81adb'),(445,'storage.write:/31bbde68-e76b-11f1-b5e7-e284dcf81adb'),(446,'storage.modify:/31bbe0a5-e76b-11f1-b5e7-e284dcf81adb'),(446,'storage.read:/31bbe0a5-e76b-11f1-b5e7-e284dcf81adb'),(446,'storage.write:/31bbe0a5-e76b-11f1-b5e7-e284dcf81adb'),(447,'storage.modify:/31bbe2e6-e76b-11f1-b5e7-e284dcf81adb'),(447,'storage.read:/31bbe2e6-e76b-11f1-b5e7-e284dcf81adb'),(447,'storage.write:/31bbe2e6-e76b-11f1-b5e7-e284dcf81adb'),(448,'storage.modify:/31bcc9ce-e76b-11f1-b5e7-e284dcf81adb'),(448,'storage.read:/31bcc9ce-e76b-11f1-b5e7-e284dcf81adb'),(448,'storage.write:/31bcc9ce-e76b-11f1-b5e7-e284dcf81adb'),(449,'storage.modify:/31bccd86-e76b-11f1-b5e7-e284dcf81adb'),(449,'storage.read:/31bccd86-e76b-11f1-b5e7-e284dcf81adb'),(449,'storage.write:/31bccd86-e76b-11f1-b5e7-e284dcf81adb'),(450,'storage.modify:/31bcd026-e76b-11f1-b5e7-e284dcf81adb'),(450,'storage.read:/31bcd026-e76b-11f1-b5e7-e284dcf81adb'),(450,'storage.write:/31bcd026-e76b-11f1-b5e7-e284dcf81adb'),(451,'storage.modify:/31bcd2ab-e76b-11f1-b5e7-e284dcf81adb'),(451,'storage.read:/31bcd2ab-e76b-11f1-b5e7-e284dcf81adb'),(451,'storage.write:/31bcd2ab-e76b-11f1-b5e7-e284dcf81adb'),(452,'storage.modify:/31bf422b-e76b-11f1-b5e7-e284dcf81adb'),(452,'storage.read:/31bf422b-e76b-11f1-b5e7-e284dcf81adb'),(452,'storage.write:/31bf422b-e76b-11f1-b5e7-e284dcf81adb'),(453,'storage.modify:/31bf475e-e76b-11f1-b5e7-e284dcf81adb'),(453,'storage.read:/31bf475e-e76b-11f1-b5e7-e284dcf81adb'),(453,'storage.write:/31bf475e-e76b-11f1-b5e7-e284dcf81adb'),(454,'storage.modify:/31bf49f2-e76b-11f1-b5e7-e284dcf81adb'),(454,'storage.read:/31bf49f2-e76b-11f1-b5e7-e284dcf81adb'),(454,'storage.write:/31bf49f2-e76b-11f1-b5e7-e284dcf81adb'),(455,'storage.modify:/31bf4c58-e76b-11f1-b5e7-e284dcf81adb'),(455,'storage.read:/31bf4c58-e76b-11f1-b5e7-e284dcf81adb'),(455,'storage.write:/31bf4c58-e76b-11f1-b5e7-e284dcf81adb'),(456,'storage.modify:/31bf4eb4-e76b-11f1-b5e7-e284dcf81adb'),(456,'storage.read:/31bf4eb4-e76b-11f1-b5e7-e284dcf81adb'),(456,'storage.write:/31bf4eb4-e76b-11f1-b5e7-e284dcf81adb'),(457,'storage.modify:/31bf5104-e76b-11f1-b5e7-e284dcf81adb'),(457,'storage.read:/31bf5104-e76b-11f1-b5e7-e284dcf81adb'),(457,'storage.write:/31bf5104-e76b-11f1-b5e7-e284dcf81adb'),(458,'storage.modify:/31bf5347-e76b-11f1-b5e7-e284dcf81adb'),(458,'storage.read:/31bf5347-e76b-11f1-b5e7-e284dcf81adb'),(458,'storage.write:/31bf5347-e76b-11f1-b5e7-e284dcf81adb'),(459,'storage.modify:/31bf5584-e76b-11f1-b5e7-e284dcf81adb'),(459,'storage.read:/31bf5584-e76b-11f1-b5e7-e284dcf81adb'),(459,'storage.write:/31bf5584-e76b-11f1-b5e7-e284dcf81adb'),(460,'storage.modify:/31bf57c1-e76b-11f1-b5e7-e284dcf81adb'),(460,'storage.read:/31bf57c1-e76b-11f1-b5e7-e284dcf81adb'),(460,'storage.write:/31bf57c1-e76b-11f1-b5e7-e284dcf81adb'),(461,'storage.modify:/31bf5a01-e76b-11f1-b5e7-e284dcf81adb'),(461,'storage.read:/31bf5a01-e76b-11f1-b5e7-e284dcf81adb'),(461,'storage.write:/31bf5a01-e76b-11f1-b5e7-e284dcf81adb'),(462,'storage.modify:/31c02440-e76b-11f1-b5e7-e284dcf81adb'),(462,'storage.read:/31c02440-e76b-11f1-b5e7-e284dcf81adb'),(462,'storage.write:/31c02440-e76b-11f1-b5e7-e284dcf81adb'),(463,'storage.modify:/31c0272f-e76b-11f1-b5e7-e284dcf81adb'),(463,'storage.read:/31c0272f-e76b-11f1-b5e7-e284dcf81adb'),(463,'storage.write:/31c0272f-e76b-11f1-b5e7-e284dcf81adb'),(464,'storage.modify:/31c0297c-e76b-11f1-b5e7-e284dcf81adb'),(464,'storage.read:/31c0297c-e76b-11f1-b5e7-e284dcf81adb'),(464,'storage.write:/31c0297c-e76b-11f1-b5e7-e284dcf81adb'),(465,'storage.modify:/31c02bce-e76b-11f1-b5e7-e284dcf81adb'),(465,'storage.read:/31c02bce-e76b-11f1-b5e7-e284dcf81adb'),(465,'storage.write:/31c02bce-e76b-11f1-b5e7-e284dcf81adb'),(466,'storage.modify:/31c02e08-e76b-11f1-b5e7-e284dcf81adb'),(466,'storage.read:/31c02e08-e76b-11f1-b5e7-e284dcf81adb'),(466,'storage.write:/31c02e08-e76b-11f1-b5e7-e284dcf81adb'),(467,'storage.modify:/31c03043-e76b-11f1-b5e7-e284dcf81adb'),(467,'storage.read:/31c03043-e76b-11f1-b5e7-e284dcf81adb'),(467,'storage.write:/31c03043-e76b-11f1-b5e7-e284dcf81adb'),(468,'storage.modify:/31c0327b-e76b-11f1-b5e7-e284dcf81adb'),(468,'storage.read:/31c0327b-e76b-11f1-b5e7-e284dcf81adb'),(468,'storage.write:/31c0327b-e76b-11f1-b5e7-e284dcf81adb'),(469,'storage.modify:/31c034b4-e76b-11f1-b5e7-e284dcf81adb'),(469,'storage.read:/31c034b4-e76b-11f1-b5e7-e284dcf81adb'),(469,'storage.write:/31c034b4-e76b-11f1-b5e7-e284dcf81adb'),(470,'storage.modify:/31c036eb-e76b-11f1-b5e7-e284dcf81adb'),(470,'storage.read:/31c036eb-e76b-11f1-b5e7-e284dcf81adb'),(470,'storage.write:/31c036eb-e76b-11f1-b5e7-e284dcf81adb'),(471,'storage.modify:/31c03921-e76b-11f1-b5e7-e284dcf81adb'),(471,'storage.read:/31c03921-e76b-11f1-b5e7-e284dcf81adb'),(471,'storage.write:/31c03921-e76b-11f1-b5e7-e284dcf81adb'),(472,'storage.modify:/31c03b57-e76b-11f1-b5e7-e284dcf81adb'),(472,'storage.read:/31c03b57-e76b-11f1-b5e7-e284dcf81adb'),(472,'storage.write:/31c03b57-e76b-11f1-b5e7-e284dcf81adb'),(473,'storage.modify:/31c03db8-e76b-11f1-b5e7-e284dcf81adb'),(473,'storage.read:/31c03db8-e76b-11f1-b5e7-e284dcf81adb'),(473,'storage.write:/31c03db8-e76b-11f1-b5e7-e284dcf81adb'),(474,'storage.modify:/31c03feb-e76b-11f1-b5e7-e284dcf81adb'),(474,'storage.read:/31c03feb-e76b-11f1-b5e7-e284dcf81adb'),(474,'storage.write:/31c03feb-e76b-11f1-b5e7-e284dcf81adb'),(475,'storage.modify:/31c04226-e76b-11f1-b5e7-e284dcf81adb'),(475,'storage.read:/31c04226-e76b-11f1-b5e7-e284dcf81adb'),(475,'storage.write:/31c04226-e76b-11f1-b5e7-e284dcf81adb'),(476,'storage.modify:/31c0446a-e76b-11f1-b5e7-e284dcf81adb'),(476,'storage.read:/31c0446a-e76b-11f1-b5e7-e284dcf81adb'),(476,'storage.write:/31c0446a-e76b-11f1-b5e7-e284dcf81adb'),(477,'storage.modify:/31c046a6-e76b-11f1-b5e7-e284dcf81adb'),(477,'storage.read:/31c046a6-e76b-11f1-b5e7-e284dcf81adb'),(477,'storage.write:/31c046a6-e76b-11f1-b5e7-e284dcf81adb'),(478,'storage.modify:/31c04915-e76b-11f1-b5e7-e284dcf81adb'),(478,'storage.read:/31c04915-e76b-11f1-b5e7-e284dcf81adb'),(478,'storage.write:/31c04915-e76b-11f1-b5e7-e284dcf81adb'),(479,'storage.modify:/31c04b5c-e76b-11f1-b5e7-e284dcf81adb'),(479,'storage.read:/31c04b5c-e76b-11f1-b5e7-e284dcf81adb'),(479,'storage.write:/31c04b5c-e76b-11f1-b5e7-e284dcf81adb'),(480,'storage.modify:/31c04dad-e76b-11f1-b5e7-e284dcf81adb'),(480,'storage.read:/31c04dad-e76b-11f1-b5e7-e284dcf81adb'),(480,'storage.write:/31c04dad-e76b-11f1-b5e7-e284dcf81adb'),(481,'storage.modify:/31c04fec-e76b-11f1-b5e7-e284dcf81adb'),(481,'storage.read:/31c04fec-e76b-11f1-b5e7-e284dcf81adb'),(481,'storage.write:/31c04fec-e76b-11f1-b5e7-e284dcf81adb'),(482,'storage.modify:/31c05222-e76b-11f1-b5e7-e284dcf81adb'),(482,'storage.read:/31c05222-e76b-11f1-b5e7-e284dcf81adb'),(482,'storage.write:/31c05222-e76b-11f1-b5e7-e284dcf81adb'),(483,'storage.modify:/31c0545d-e76b-11f1-b5e7-e284dcf81adb'),(483,'storage.read:/31c0545d-e76b-11f1-b5e7-e284dcf81adb'),(483,'storage.write:/31c0545d-e76b-11f1-b5e7-e284dcf81adb'),(484,'storage.modify:/31c05698-e76b-11f1-b5e7-e284dcf81adb'),(484,'storage.read:/31c05698-e76b-11f1-b5e7-e284dcf81adb'),(484,'storage.write:/31c05698-e76b-11f1-b5e7-e284dcf81adb'),(485,'storage.modify:/31c058d2-e76b-11f1-b5e7-e284dcf81adb'),(485,'storage.read:/31c058d2-e76b-11f1-b5e7-e284dcf81adb'),(485,'storage.write:/31c058d2-e76b-11f1-b5e7-e284dcf81adb'),(486,'storage.modify:/31c05b05-e76b-11f1-b5e7-e284dcf81adb'),(486,'storage.read:/31c05b05-e76b-11f1-b5e7-e284dcf81adb'),(486,'storage.write:/31c05b05-e76b-11f1-b5e7-e284dcf81adb'),(487,'storage.modify:/31c05d39-e76b-11f1-b5e7-e284dcf81adb'),(487,'storage.read:/31c05d39-e76b-11f1-b5e7-e284dcf81adb'),(487,'storage.write:/31c05d39-e76b-11f1-b5e7-e284dcf81adb'),(488,'storage.modify:/31c05f6e-e76b-11f1-b5e7-e284dcf81adb'),(488,'storage.read:/31c05f6e-e76b-11f1-b5e7-e284dcf81adb'),(488,'storage.write:/31c05f6e-e76b-11f1-b5e7-e284dcf81adb'),(489,'storage.modify:/31c061a7-e76b-11f1-b5e7-e284dcf81adb'),(489,'storage.read:/31c061a7-e76b-11f1-b5e7-e284dcf81adb'),(489,'storage.write:/31c061a7-e76b-11f1-b5e7-e284dcf81adb'),(490,'storage.modify:/31c063fd-e76b-11f1-b5e7-e284dcf81adb'),(490,'storage.read:/31c063fd-e76b-11f1-b5e7-e284dcf81adb'),(490,'storage.write:/31c063fd-e76b-11f1-b5e7-e284dcf81adb'),(491,'storage.modify:/31c0663b-e76b-11f1-b5e7-e284dcf81adb'),(491,'storage.read:/31c0663b-e76b-11f1-b5e7-e284dcf81adb'),(491,'storage.write:/31c0663b-e76b-11f1-b5e7-e284dcf81adb'),(492,'storage.modify:/31c0687e-e76b-11f1-b5e7-e284dcf81adb'),(492,'storage.read:/31c0687e-e76b-11f1-b5e7-e284dcf81adb'),(492,'storage.write:/31c0687e-e76b-11f1-b5e7-e284dcf81adb'),(493,'storage.modify:/31c06ab9-e76b-11f1-b5e7-e284dcf81adb'),(493,'storage.read:/31c06ab9-e76b-11f1-b5e7-e284dcf81adb'),(493,'storage.write:/31c06ab9-e76b-11f1-b5e7-e284dcf81adb'),(494,'storage.modify:/31c06ced-e76b-11f1-b5e7-e284dcf81adb'),(494,'storage.read:/31c06ced-e76b-11f1-b5e7-e284dcf81adb'),(494,'storage.write:/31c06ced-e76b-11f1-b5e7-e284dcf81adb'),(495,'storage.modify:/31c06f26-e76b-11f1-b5e7-e284dcf81adb'),(495,'storage.read:/31c06f26-e76b-11f1-b5e7-e284dcf81adb'),(495,'storage.write:/31c06f26-e76b-11f1-b5e7-e284dcf81adb'),(496,'storage.modify:/31c071cc-e76b-11f1-b5e7-e284dcf81adb'),(496,'storage.read:/31c071cc-e76b-11f1-b5e7-e284dcf81adb'),(496,'storage.write:/31c071cc-e76b-11f1-b5e7-e284dcf81adb'),(497,'storage.modify:/31c07461-e76b-11f1-b5e7-e284dcf81adb'),(497,'storage.read:/31c07461-e76b-11f1-b5e7-e284dcf81adb'),(497,'storage.write:/31c07461-e76b-11f1-b5e7-e284dcf81adb'),(498,'storage.modify:/31c076ab-e76b-11f1-b5e7-e284dcf81adb'),(498,'storage.read:/31c076ab-e76b-11f1-b5e7-e284dcf81adb'),(498,'storage.write:/31c076ab-e76b-11f1-b5e7-e284dcf81adb'),(499,'storage.modify:/31c078ec-e76b-11f1-b5e7-e284dcf81adb'),(499,'storage.read:/31c078ec-e76b-11f1-b5e7-e284dcf81adb'),(499,'storage.write:/31c078ec-e76b-11f1-b5e7-e284dcf81adb'),(500,'storage.modify:/31c07b33-e76b-11f1-b5e7-e284dcf81adb'),(500,'storage.read:/31c07b33-e76b-11f1-b5e7-e284dcf81adb'),(500,'storage.write:/31c07b33-e76b-11f1-b5e7-e284dcf81adb'),(501,'storage.modify:/31c07d79-e76b-11f1-b5e7-e284dcf81adb'),(501,'storage.read:/31c07d79-e76b-11f1-b5e7-e284dcf81adb'),(501,'storage.write:/31c07d79-e76b-11f1-b5e7-e284dcf81adb'),(502,'storage.modify:/31c07fb8-e76b-11f1-b5e7-e284dcf81adb'),(502,'storage.read:/31c07fb8-e76b-11f1-b5e7-e284dcf81adb'),(502,'storage.write:/31c07fb8-e76b-11f1-b5e7-e284dcf81adb'),(503,'storage.modify:/31c081f0-e76b-11f1-b5e7-e284dcf81adb'),(503,'storage.read:/31c081f0-e76b-11f1-b5e7-e284dcf81adb'),(503,'storage.write:/31c081f0-e76b-11f1-b5e7-e284dcf81adb'),(504,'storage.modify:/31c0842f-e76b-11f1-b5e7-e284dcf81adb'),(504,'storage.read:/31c0842f-e76b-11f1-b5e7-e284dcf81adb'),(504,'storage.write:/31c0842f-e76b-11f1-b5e7-e284dcf81adb'),(505,'storage.modify:/31c08672-e76b-11f1-b5e7-e284dcf81adb'),(505,'storage.read:/31c08672-e76b-11f1-b5e7-e284dcf81adb'),(505,'storage.write:/31c08672-e76b-11f1-b5e7-e284dcf81adb'),(506,'storage.modify:/31c088b2-e76b-11f1-b5e7-e284dcf81adb'),(506,'storage.read:/31c088b2-e76b-11f1-b5e7-e284dcf81adb'),(506,'storage.write:/31c088b2-e76b-11f1-b5e7-e284dcf81adb'),(507,'storage.modify:/31c19e09-e76b-11f1-b5e7-e284dcf81adb'),(507,'storage.read:/31c19e09-e76b-11f1-b5e7-e284dcf81adb'),(507,'storage.write:/31c19e09-e76b-11f1-b5e7-e284dcf81adb'),(508,'storage.modify:/31c321a0-e76b-11f1-b5e7-e284dcf81adb'),(508,'storage.read:/31c321a0-e76b-11f1-b5e7-e284dcf81adb'),(508,'storage.write:/31c321a0-e76b-11f1-b5e7-e284dcf81adb'),(509,'storage.modify:/31c32753-e76b-11f1-b5e7-e284dcf81adb'),(509,'storage.read:/31c32753-e76b-11f1-b5e7-e284dcf81adb'),(509,'storage.write:/31c32753-e76b-11f1-b5e7-e284dcf81adb'),(510,'storage.modify:/31c329ef-e76b-11f1-b5e7-e284dcf81adb'),(510,'storage.read:/31c329ef-e76b-11f1-b5e7-e284dcf81adb'),(510,'storage.write:/31c329ef-e76b-11f1-b5e7-e284dcf81adb'),(511,'storage.modify:/31c32c59-e76b-11f1-b5e7-e284dcf81adb'),(511,'storage.read:/31c32c59-e76b-11f1-b5e7-e284dcf81adb'),(511,'storage.write:/31c32c59-e76b-11f1-b5e7-e284dcf81adb'),(512,'storage.modify:/31c32ef1-e76b-11f1-b5e7-e284dcf81adb'),(512,'storage.read:/31c32ef1-e76b-11f1-b5e7-e284dcf81adb'),(512,'storage.write:/31c32ef1-e76b-11f1-b5e7-e284dcf81adb'),(513,'storage.modify:/31c3315b-e76b-11f1-b5e7-e284dcf81adb'),(513,'storage.read:/31c3315b-e76b-11f1-b5e7-e284dcf81adb'),(513,'storage.write:/31c3315b-e76b-11f1-b5e7-e284dcf81adb'),(514,'storage.modify:/31c333ab-e76b-11f1-b5e7-e284dcf81adb'),(514,'storage.read:/31c333ab-e76b-11f1-b5e7-e284dcf81adb'),(514,'storage.write:/31c333ab-e76b-11f1-b5e7-e284dcf81adb'),(515,'storage.modify:/31c335f4-e76b-11f1-b5e7-e284dcf81adb'),(515,'storage.read:/31c335f4-e76b-11f1-b5e7-e284dcf81adb'),(515,'storage.write:/31c335f4-e76b-11f1-b5e7-e284dcf81adb'),(516,'storage.modify:/31c33836-e76b-11f1-b5e7-e284dcf81adb'),(516,'storage.read:/31c33836-e76b-11f1-b5e7-e284dcf81adb'),(516,'storage.write:/31c33836-e76b-11f1-b5e7-e284dcf81adb'),(517,'storage.modify:/31c33a7c-e76b-11f1-b5e7-e284dcf81adb'),(517,'storage.read:/31c33a7c-e76b-11f1-b5e7-e284dcf81adb'),(517,'storage.write:/31c33a7c-e76b-11f1-b5e7-e284dcf81adb'),(518,'storage.modify:/31c33cc3-e76b-11f1-b5e7-e284dcf81adb'),(518,'storage.read:/31c33cc3-e76b-11f1-b5e7-e284dcf81adb'),(518,'storage.write:/31c33cc3-e76b-11f1-b5e7-e284dcf81adb'),(519,'storage.modify:/31c33eff-e76b-11f1-b5e7-e284dcf81adb'),(519,'storage.read:/31c33eff-e76b-11f1-b5e7-e284dcf81adb'),(519,'storage.write:/31c33eff-e76b-11f1-b5e7-e284dcf81adb'),(520,'storage.modify:/31c34146-e76b-11f1-b5e7-e284dcf81adb'),(520,'storage.read:/31c34146-e76b-11f1-b5e7-e284dcf81adb'),(520,'storage.write:/31c34146-e76b-11f1-b5e7-e284dcf81adb'),(521,'storage.modify:/31c34388-e76b-11f1-b5e7-e284dcf81adb'),(521,'storage.read:/31c34388-e76b-11f1-b5e7-e284dcf81adb'),(521,'storage.write:/31c34388-e76b-11f1-b5e7-e284dcf81adb'),(522,'storage.modify:/31c345e9-e76b-11f1-b5e7-e284dcf81adb'),(522,'storage.read:/31c345e9-e76b-11f1-b5e7-e284dcf81adb'),(522,'storage.write:/31c345e9-e76b-11f1-b5e7-e284dcf81adb'),(523,'storage.modify:/31c348bc-e76b-11f1-b5e7-e284dcf81adb'),(523,'storage.read:/31c348bc-e76b-11f1-b5e7-e284dcf81adb'),(523,'storage.write:/31c348bc-e76b-11f1-b5e7-e284dcf81adb'),(524,'storage.modify:/31c34b13-e76b-11f1-b5e7-e284dcf81adb'),(524,'storage.read:/31c34b13-e76b-11f1-b5e7-e284dcf81adb'),(524,'storage.write:/31c34b13-e76b-11f1-b5e7-e284dcf81adb'),(525,'storage.modify:/31c34d60-e76b-11f1-b5e7-e284dcf81adb'),(525,'storage.read:/31c34d60-e76b-11f1-b5e7-e284dcf81adb'),(525,'storage.write:/31c34d60-e76b-11f1-b5e7-e284dcf81adb'),(526,'storage.modify:/31c34fac-e76b-11f1-b5e7-e284dcf81adb'),(526,'storage.read:/31c34fac-e76b-11f1-b5e7-e284dcf81adb'),(526,'storage.write:/31c34fac-e76b-11f1-b5e7-e284dcf81adb'),(527,'storage.modify:/31c51a98-e76b-11f1-b5e7-e284dcf81adb'),(527,'storage.read:/31c51a98-e76b-11f1-b5e7-e284dcf81adb'),(527,'storage.write:/31c51a98-e76b-11f1-b5e7-e284dcf81adb'),(528,'storage.modify:/31c51ffc-e76b-11f1-b5e7-e284dcf81adb'),(528,'storage.read:/31c51ffc-e76b-11f1-b5e7-e284dcf81adb'),(528,'storage.write:/31c51ffc-e76b-11f1-b5e7-e284dcf81adb'),(529,'storage.modify:/31c69870-e76b-11f1-b5e7-e284dcf81adb'),(529,'storage.read:/31c69870-e76b-11f1-b5e7-e284dcf81adb'),(529,'storage.write:/31c69870-e76b-11f1-b5e7-e284dcf81adb'),(530,'storage.modify:/31c69ccc-e76b-11f1-b5e7-e284dcf81adb'),(530,'storage.read:/31c69ccc-e76b-11f1-b5e7-e284dcf81adb'),(530,'storage.write:/31c69ccc-e76b-11f1-b5e7-e284dcf81adb'),(531,'storage.modify:/31c69f4f-e76b-11f1-b5e7-e284dcf81adb'),(531,'storage.read:/31c69f4f-e76b-11f1-b5e7-e284dcf81adb'),(531,'storage.write:/31c69f4f-e76b-11f1-b5e7-e284dcf81adb'),(532,'storage.modify:/31c6a1c8-e76b-11f1-b5e7-e284dcf81adb'),(532,'storage.read:/31c6a1c8-e76b-11f1-b5e7-e284dcf81adb'),(532,'storage.write:/31c6a1c8-e76b-11f1-b5e7-e284dcf81adb'),(533,'storage.modify:/31c6a562-e76b-11f1-b5e7-e284dcf81adb'),(533,'storage.read:/31c6a562-e76b-11f1-b5e7-e284dcf81adb'),(533,'storage.write:/31c6a562-e76b-11f1-b5e7-e284dcf81adb'),(534,'storage.modify:/31c6a7bf-e76b-11f1-b5e7-e284dcf81adb'),(534,'storage.read:/31c6a7bf-e76b-11f1-b5e7-e284dcf81adb'),(534,'storage.write:/31c6a7bf-e76b-11f1-b5e7-e284dcf81adb'),(535,'storage.modify:/31c6aa13-e76b-11f1-b5e7-e284dcf81adb'),(535,'storage.read:/31c6aa13-e76b-11f1-b5e7-e284dcf81adb'),(535,'storage.write:/31c6aa13-e76b-11f1-b5e7-e284dcf81adb'),(536,'storage.modify:/31c6ac5d-e76b-11f1-b5e7-e284dcf81adb'),(536,'storage.read:/31c6ac5d-e76b-11f1-b5e7-e284dcf81adb'),(536,'storage.write:/31c6ac5d-e76b-11f1-b5e7-e284dcf81adb'),(537,'storage.modify:/31c6aeb2-e76b-11f1-b5e7-e284dcf81adb'),(537,'storage.read:/31c6aeb2-e76b-11f1-b5e7-e284dcf81adb'),(537,'storage.write:/31c6aeb2-e76b-11f1-b5e7-e284dcf81adb'),(538,'storage.modify:/31c6b153-e76b-11f1-b5e7-e284dcf81adb'),(538,'storage.read:/31c6b153-e76b-11f1-b5e7-e284dcf81adb'),(538,'storage.write:/31c6b153-e76b-11f1-b5e7-e284dcf81adb'),(539,'storage.modify:/31c6b3ba-e76b-11f1-b5e7-e284dcf81adb'),(539,'storage.read:/31c6b3ba-e76b-11f1-b5e7-e284dcf81adb'),(539,'storage.write:/31c6b3ba-e76b-11f1-b5e7-e284dcf81adb'),(540,'storage.modify:/31c6b605-e76b-11f1-b5e7-e284dcf81adb'),(540,'storage.read:/31c6b605-e76b-11f1-b5e7-e284dcf81adb'),(540,'storage.write:/31c6b605-e76b-11f1-b5e7-e284dcf81adb'),(541,'storage.modify:/31c6b849-e76b-11f1-b5e7-e284dcf81adb'),(541,'storage.read:/31c6b849-e76b-11f1-b5e7-e284dcf81adb'),(541,'storage.write:/31c6b849-e76b-11f1-b5e7-e284dcf81adb'),(542,'storage.modify:/31c6ba8d-e76b-11f1-b5e7-e284dcf81adb'),(542,'storage.read:/31c6ba8d-e76b-11f1-b5e7-e284dcf81adb'),(542,'storage.write:/31c6ba8d-e76b-11f1-b5e7-e284dcf81adb'),(543,'storage.modify:/31c6bcd1-e76b-11f1-b5e7-e284dcf81adb'),(543,'storage.read:/31c6bcd1-e76b-11f1-b5e7-e284dcf81adb'),(543,'storage.write:/31c6bcd1-e76b-11f1-b5e7-e284dcf81adb'),(544,'storage.modify:/31c6bf15-e76b-11f1-b5e7-e284dcf81adb'),(544,'storage.read:/31c6bf15-e76b-11f1-b5e7-e284dcf81adb'),(544,'storage.write:/31c6bf15-e76b-11f1-b5e7-e284dcf81adb'),(545,'storage.modify:/31c6c158-e76b-11f1-b5e7-e284dcf81adb'),(545,'storage.read:/31c6c158-e76b-11f1-b5e7-e284dcf81adb'),(545,'storage.write:/31c6c158-e76b-11f1-b5e7-e284dcf81adb'),(546,'storage.modify:/31c6c3a5-e76b-11f1-b5e7-e284dcf81adb'),(546,'storage.read:/31c6c3a5-e76b-11f1-b5e7-e284dcf81adb'),(546,'storage.write:/31c6c3a5-e76b-11f1-b5e7-e284dcf81adb'),(547,'storage.modify:/31c6c5b6-e76b-11f1-b5e7-e284dcf81adb'),(547,'storage.read:/31c6c5b6-e76b-11f1-b5e7-e284dcf81adb'),(547,'storage.write:/31c6c5b6-e76b-11f1-b5e7-e284dcf81adb'),(548,'storage.modify:/31c6c850-e76b-11f1-b5e7-e284dcf81adb'),(548,'storage.read:/31c6c850-e76b-11f1-b5e7-e284dcf81adb'),(548,'storage.write:/31c6c850-e76b-11f1-b5e7-e284dcf81adb'),(549,'storage.modify:/31c6cb42-e76b-11f1-b5e7-e284dcf81adb'),(549,'storage.read:/31c6cb42-e76b-11f1-b5e7-e284dcf81adb'),(549,'storage.write:/31c6cb42-e76b-11f1-b5e7-e284dcf81adb'),(550,'storage.modify:/31c6cd84-e76b-11f1-b5e7-e284dcf81adb'),(550,'storage.read:/31c6cd84-e76b-11f1-b5e7-e284dcf81adb'),(550,'storage.write:/31c6cd84-e76b-11f1-b5e7-e284dcf81adb'),(551,'storage.modify:/31c6cfce-e76b-11f1-b5e7-e284dcf81adb'),(551,'storage.read:/31c6cfce-e76b-11f1-b5e7-e284dcf81adb'),(551,'storage.write:/31c6cfce-e76b-11f1-b5e7-e284dcf81adb'),(552,'storage.modify:/31c6d21a-e76b-11f1-b5e7-e284dcf81adb'),(552,'storage.read:/31c6d21a-e76b-11f1-b5e7-e284dcf81adb'),(552,'storage.write:/31c6d21a-e76b-11f1-b5e7-e284dcf81adb'),(553,'storage.modify:/31c6d461-e76b-11f1-b5e7-e284dcf81adb'),(553,'storage.read:/31c6d461-e76b-11f1-b5e7-e284dcf81adb'),(553,'storage.write:/31c6d461-e76b-11f1-b5e7-e284dcf81adb'),(554,'storage.modify:/31c6d6a6-e76b-11f1-b5e7-e284dcf81adb'),(554,'storage.read:/31c6d6a6-e76b-11f1-b5e7-e284dcf81adb'),(554,'storage.write:/31c6d6a6-e76b-11f1-b5e7-e284dcf81adb'),(555,'storage.modify:/31c6d916-e76b-11f1-b5e7-e284dcf81adb'),(555,'storage.read:/31c6d916-e76b-11f1-b5e7-e284dcf81adb'),(555,'storage.write:/31c6d916-e76b-11f1-b5e7-e284dcf81adb'),(556,'storage.modify:/31c6dbab-e76b-11f1-b5e7-e284dcf81adb'),(556,'storage.read:/31c6dbab-e76b-11f1-b5e7-e284dcf81adb'),(556,'storage.write:/31c6dbab-e76b-11f1-b5e7-e284dcf81adb'),(557,'storage.modify:/31c6ddf5-e76b-11f1-b5e7-e284dcf81adb'),(557,'storage.read:/31c6ddf5-e76b-11f1-b5e7-e284dcf81adb'),(557,'storage.write:/31c6ddf5-e76b-11f1-b5e7-e284dcf81adb'),(558,'storage.modify:/31c6e035-e76b-11f1-b5e7-e284dcf81adb'),(558,'storage.read:/31c6e035-e76b-11f1-b5e7-e284dcf81adb'),(558,'storage.write:/31c6e035-e76b-11f1-b5e7-e284dcf81adb'),(559,'storage.modify:/31c6e277-e76b-11f1-b5e7-e284dcf81adb'),(559,'storage.read:/31c6e277-e76b-11f1-b5e7-e284dcf81adb'),(559,'storage.write:/31c6e277-e76b-11f1-b5e7-e284dcf81adb'),(560,'storage.modify:/31c6e4c4-e76b-11f1-b5e7-e284dcf81adb'),(560,'storage.read:/31c6e4c4-e76b-11f1-b5e7-e284dcf81adb'),(560,'storage.write:/31c6e4c4-e76b-11f1-b5e7-e284dcf81adb'),(561,'storage.modify:/31c6e70c-e76b-11f1-b5e7-e284dcf81adb'),(561,'storage.read:/31c6e70c-e76b-11f1-b5e7-e284dcf81adb'),(561,'storage.write:/31c6e70c-e76b-11f1-b5e7-e284dcf81adb'),(562,'storage.modify:/31c6e953-e76b-11f1-b5e7-e284dcf81adb'),(562,'storage.read:/31c6e953-e76b-11f1-b5e7-e284dcf81adb'),(562,'storage.write:/31c6e953-e76b-11f1-b5e7-e284dcf81adb'),(563,'storage.modify:/31c6ec01-e76b-11f1-b5e7-e284dcf81adb'),(563,'storage.read:/31c6ec01-e76b-11f1-b5e7-e284dcf81adb'),(563,'storage.write:/31c6ec01-e76b-11f1-b5e7-e284dcf81adb'),(564,'storage.modify:/31c81b64-e76b-11f1-b5e7-e284dcf81adb'),(564,'storage.read:/31c81b64-e76b-11f1-b5e7-e284dcf81adb'),(564,'storage.write:/31c81b64-e76b-11f1-b5e7-e284dcf81adb'),(565,'storage.modify:/31c8219a-e76b-11f1-b5e7-e284dcf81adb'),(565,'storage.read:/31c8219a-e76b-11f1-b5e7-e284dcf81adb'),(565,'storage.write:/31c8219a-e76b-11f1-b5e7-e284dcf81adb'),(566,'storage.modify:/31c99c4d-e76b-11f1-b5e7-e284dcf81adb'),(566,'storage.read:/31c99c4d-e76b-11f1-b5e7-e284dcf81adb'),(566,'storage.write:/31c99c4d-e76b-11f1-b5e7-e284dcf81adb'),(567,'storage.modify:/31c9a28f-e76b-11f1-b5e7-e284dcf81adb'),(567,'storage.read:/31c9a28f-e76b-11f1-b5e7-e284dcf81adb'),(567,'storage.write:/31c9a28f-e76b-11f1-b5e7-e284dcf81adb'),(568,'storage.modify:/31c9a51d-e76b-11f1-b5e7-e284dcf81adb'),(568,'storage.read:/31c9a51d-e76b-11f1-b5e7-e284dcf81adb'),(568,'storage.write:/31c9a51d-e76b-11f1-b5e7-e284dcf81adb'),(569,'storage.modify:/31c9a789-e76b-11f1-b5e7-e284dcf81adb'),(569,'storage.read:/31c9a789-e76b-11f1-b5e7-e284dcf81adb'),(569,'storage.write:/31c9a789-e76b-11f1-b5e7-e284dcf81adb'),(570,'storage.modify:/31c9a9e0-e76b-11f1-b5e7-e284dcf81adb'),(570,'storage.read:/31c9a9e0-e76b-11f1-b5e7-e284dcf81adb'),(570,'storage.write:/31c9a9e0-e76b-11f1-b5e7-e284dcf81adb'),(571,'storage.modify:/31c9ac33-e76b-11f1-b5e7-e284dcf81adb'),(571,'storage.read:/31c9ac33-e76b-11f1-b5e7-e284dcf81adb'),(571,'storage.write:/31c9ac33-e76b-11f1-b5e7-e284dcf81adb'),(572,'storage.modify:/31c9ae89-e76b-11f1-b5e7-e284dcf81adb'),(572,'storage.read:/31c9ae89-e76b-11f1-b5e7-e284dcf81adb'),(572,'storage.write:/31c9ae89-e76b-11f1-b5e7-e284dcf81adb'),(573,'storage.modify:/31c9b0d7-e76b-11f1-b5e7-e284dcf81adb'),(573,'storage.read:/31c9b0d7-e76b-11f1-b5e7-e284dcf81adb'),(573,'storage.write:/31c9b0d7-e76b-11f1-b5e7-e284dcf81adb'),(574,'storage.modify:/31c9b32b-e76b-11f1-b5e7-e284dcf81adb'),(574,'storage.read:/31c9b32b-e76b-11f1-b5e7-e284dcf81adb'),(574,'storage.write:/31c9b32b-e76b-11f1-b5e7-e284dcf81adb'),(575,'storage.modify:/31c9b57a-e76b-11f1-b5e7-e284dcf81adb'),(575,'storage.read:/31c9b57a-e76b-11f1-b5e7-e284dcf81adb'),(575,'storage.write:/31c9b57a-e76b-11f1-b5e7-e284dcf81adb'),(576,'storage.modify:/31c9b7c8-e76b-11f1-b5e7-e284dcf81adb'),(576,'storage.read:/31c9b7c8-e76b-11f1-b5e7-e284dcf81adb'),(576,'storage.write:/31c9b7c8-e76b-11f1-b5e7-e284dcf81adb'),(577,'storage.modify:/31c9ba11-e76b-11f1-b5e7-e284dcf81adb'),(577,'storage.read:/31c9ba11-e76b-11f1-b5e7-e284dcf81adb'),(577,'storage.write:/31c9ba11-e76b-11f1-b5e7-e284dcf81adb'),(578,'storage.modify:/31c9bc5a-e76b-11f1-b5e7-e284dcf81adb'),(578,'storage.read:/31c9bc5a-e76b-11f1-b5e7-e284dcf81adb'),(578,'storage.write:/31c9bc5a-e76b-11f1-b5e7-e284dcf81adb'),(579,'storage.modify:/31c9befe-e76b-11f1-b5e7-e284dcf81adb'),(579,'storage.read:/31c9befe-e76b-11f1-b5e7-e284dcf81adb'),(579,'storage.write:/31c9befe-e76b-11f1-b5e7-e284dcf81adb'),(580,'storage.modify:/31c9c164-e76b-11f1-b5e7-e284dcf81adb'),(580,'storage.read:/31c9c164-e76b-11f1-b5e7-e284dcf81adb'),(580,'storage.write:/31c9c164-e76b-11f1-b5e7-e284dcf81adb'),(581,'storage.modify:/31c9c3b1-e76b-11f1-b5e7-e284dcf81adb'),(581,'storage.read:/31c9c3b1-e76b-11f1-b5e7-e284dcf81adb'),(581,'storage.write:/31c9c3b1-e76b-11f1-b5e7-e284dcf81adb'),(582,'storage.modify:/31c9c5fd-e76b-11f1-b5e7-e284dcf81adb'),(582,'storage.read:/31c9c5fd-e76b-11f1-b5e7-e284dcf81adb'),(582,'storage.write:/31c9c5fd-e76b-11f1-b5e7-e284dcf81adb'),(583,'storage.modify:/31c9c847-e76b-11f1-b5e7-e284dcf81adb'),(583,'storage.read:/31c9c847-e76b-11f1-b5e7-e284dcf81adb'),(583,'storage.write:/31c9c847-e76b-11f1-b5e7-e284dcf81adb'),(584,'storage.modify:/31c9ca92-e76b-11f1-b5e7-e284dcf81adb'),(584,'storage.read:/31c9ca92-e76b-11f1-b5e7-e284dcf81adb'),(584,'storage.write:/31c9ca92-e76b-11f1-b5e7-e284dcf81adb'),(585,'storage.modify:/31c9ccde-e76b-11f1-b5e7-e284dcf81adb'),(585,'storage.read:/31c9ccde-e76b-11f1-b5e7-e284dcf81adb'),(585,'storage.write:/31c9ccde-e76b-11f1-b5e7-e284dcf81adb'),(586,'storage.modify:/31c9cf28-e76b-11f1-b5e7-e284dcf81adb'),(586,'storage.read:/31c9cf28-e76b-11f1-b5e7-e284dcf81adb'),(586,'storage.write:/31c9cf28-e76b-11f1-b5e7-e284dcf81adb'),(587,'storage.modify:/31c9d172-e76b-11f1-b5e7-e284dcf81adb'),(587,'storage.read:/31c9d172-e76b-11f1-b5e7-e284dcf81adb'),(587,'storage.write:/31c9d172-e76b-11f1-b5e7-e284dcf81adb'),(588,'storage.modify:/31c9d3c0-e76b-11f1-b5e7-e284dcf81adb'),(588,'storage.read:/31c9d3c0-e76b-11f1-b5e7-e284dcf81adb'),(588,'storage.write:/31c9d3c0-e76b-11f1-b5e7-e284dcf81adb'),(589,'storage.modify:/31c9d60c-e76b-11f1-b5e7-e284dcf81adb'),(589,'storage.read:/31c9d60c-e76b-11f1-b5e7-e284dcf81adb'),(589,'storage.write:/31c9d60c-e76b-11f1-b5e7-e284dcf81adb'),(590,'storage.modify:/31c9d837-e76b-11f1-b5e7-e284dcf81adb'),(590,'storage.read:/31c9d837-e76b-11f1-b5e7-e284dcf81adb'),(590,'storage.write:/31c9d837-e76b-11f1-b5e7-e284dcf81adb'),(591,'storage.modify:/31c9da4a-e76b-11f1-b5e7-e284dcf81adb'),(591,'storage.read:/31c9da4a-e76b-11f1-b5e7-e284dcf81adb'),(591,'storage.write:/31c9da4a-e76b-11f1-b5e7-e284dcf81adb'),(592,'storage.modify:/31c9dc6d-e76b-11f1-b5e7-e284dcf81adb'),(592,'storage.read:/31c9dc6d-e76b-11f1-b5e7-e284dcf81adb'),(592,'storage.write:/31c9dc6d-e76b-11f1-b5e7-e284dcf81adb'),(593,'storage.modify:/31c9de81-e76b-11f1-b5e7-e284dcf81adb'),(593,'storage.read:/31c9de81-e76b-11f1-b5e7-e284dcf81adb'),(593,'storage.write:/31c9de81-e76b-11f1-b5e7-e284dcf81adb'),(594,'storage.modify:/31c9e092-e76b-11f1-b5e7-e284dcf81adb'),(594,'storage.read:/31c9e092-e76b-11f1-b5e7-e284dcf81adb'),(594,'storage.write:/31c9e092-e76b-11f1-b5e7-e284dcf81adb'),(595,'storage.modify:/31c9e2a6-e76b-11f1-b5e7-e284dcf81adb'),(595,'storage.read:/31c9e2a6-e76b-11f1-b5e7-e284dcf81adb'),(595,'storage.write:/31c9e2a6-e76b-11f1-b5e7-e284dcf81adb'),(596,'storage.modify:/31c9e4b7-e76b-11f1-b5e7-e284dcf81adb'),(596,'storage.read:/31c9e4b7-e76b-11f1-b5e7-e284dcf81adb'),(596,'storage.write:/31c9e4b7-e76b-11f1-b5e7-e284dcf81adb'),(597,'storage.modify:/31c9e814-e76b-11f1-b5e7-e284dcf81adb'),(597,'storage.read:/31c9e814-e76b-11f1-b5e7-e284dcf81adb'),(597,'storage.write:/31c9e814-e76b-11f1-b5e7-e284dcf81adb'),(598,'storage.modify:/31c9ea77-e76b-11f1-b5e7-e284dcf81adb'),(598,'storage.read:/31c9ea77-e76b-11f1-b5e7-e284dcf81adb'),(598,'storage.write:/31c9ea77-e76b-11f1-b5e7-e284dcf81adb'),(599,'storage.modify:/31c9ee5e-e76b-11f1-b5e7-e284dcf81adb'),(599,'storage.read:/31c9ee5e-e76b-11f1-b5e7-e284dcf81adb'),(599,'storage.write:/31c9ee5e-e76b-11f1-b5e7-e284dcf81adb'),(600,'storage.modify:/31c9f0e9-e76b-11f1-b5e7-e284dcf81adb'),(600,'storage.read:/31c9f0e9-e76b-11f1-b5e7-e284dcf81adb'),(600,'storage.write:/31c9f0e9-e76b-11f1-b5e7-e284dcf81adb'),(601,'storage.modify:/31c9f342-e76b-11f1-b5e7-e284dcf81adb'),(601,'storage.read:/31c9f342-e76b-11f1-b5e7-e284dcf81adb'),(601,'storage.write:/31c9f342-e76b-11f1-b5e7-e284dcf81adb'),(602,'storage.modify:/31ccef5e-e76b-11f1-b5e7-e284dcf81adb'),(602,'storage.read:/31ccef5e-e76b-11f1-b5e7-e284dcf81adb'),(602,'storage.write:/31ccef5e-e76b-11f1-b5e7-e284dcf81adb'),(603,'storage.modify:/31ccf4d3-e76b-11f1-b5e7-e284dcf81adb'),(603,'storage.read:/31ccf4d3-e76b-11f1-b5e7-e284dcf81adb'),(603,'storage.write:/31ccf4d3-e76b-11f1-b5e7-e284dcf81adb'),(604,'storage.modify:/31ccf8f8-e76b-11f1-b5e7-e284dcf81adb'),(604,'storage.read:/31ccf8f8-e76b-11f1-b5e7-e284dcf81adb'),(604,'storage.write:/31ccf8f8-e76b-11f1-b5e7-e284dcf81adb'),(605,'storage.modify:/31ccfb98-e76b-11f1-b5e7-e284dcf81adb'),(605,'storage.read:/31ccfb98-e76b-11f1-b5e7-e284dcf81adb'),(605,'storage.write:/31ccfb98-e76b-11f1-b5e7-e284dcf81adb'),(606,'storage.modify:/31ccfe2f-e76b-11f1-b5e7-e284dcf81adb'),(606,'storage.read:/31ccfe2f-e76b-11f1-b5e7-e284dcf81adb'),(606,'storage.write:/31ccfe2f-e76b-11f1-b5e7-e284dcf81adb'),(607,'storage.modify:/31cd00c0-e76b-11f1-b5e7-e284dcf81adb'),(607,'storage.read:/31cd00c0-e76b-11f1-b5e7-e284dcf81adb'),(607,'storage.write:/31cd00c0-e76b-11f1-b5e7-e284dcf81adb'),(608,'storage.modify:/31cd0307-e76b-11f1-b5e7-e284dcf81adb'),(608,'storage.read:/31cd0307-e76b-11f1-b5e7-e284dcf81adb'),(608,'storage.write:/31cd0307-e76b-11f1-b5e7-e284dcf81adb'),(609,'storage.modify:/31cd05cf-e76b-11f1-b5e7-e284dcf81adb'),(609,'storage.read:/31cd05cf-e76b-11f1-b5e7-e284dcf81adb'),(609,'storage.write:/31cd05cf-e76b-11f1-b5e7-e284dcf81adb'),(610,'storage.modify:/31cd0851-e76b-11f1-b5e7-e284dcf81adb'),(610,'storage.read:/31cd0851-e76b-11f1-b5e7-e284dcf81adb'),(610,'storage.write:/31cd0851-e76b-11f1-b5e7-e284dcf81adb'),(611,'storage.modify:/31cd0b0c-e76b-11f1-b5e7-e284dcf81adb'),(611,'storage.read:/31cd0b0c-e76b-11f1-b5e7-e284dcf81adb'),(611,'storage.write:/31cd0b0c-e76b-11f1-b5e7-e284dcf81adb'),(612,'storage.modify:/31cd0dbb-e76b-11f1-b5e7-e284dcf81adb'),(612,'storage.read:/31cd0dbb-e76b-11f1-b5e7-e284dcf81adb'),(612,'storage.write:/31cd0dbb-e76b-11f1-b5e7-e284dcf81adb'),(613,'storage.modify:/31cd107f-e76b-11f1-b5e7-e284dcf81adb'),(613,'storage.read:/31cd107f-e76b-11f1-b5e7-e284dcf81adb'),(613,'storage.write:/31cd107f-e76b-11f1-b5e7-e284dcf81adb'),(614,'storage.modify:/31cd12e9-e76b-11f1-b5e7-e284dcf81adb'),(614,'storage.read:/31cd12e9-e76b-11f1-b5e7-e284dcf81adb'),(614,'storage.write:/31cd12e9-e76b-11f1-b5e7-e284dcf81adb'),(615,'storage.modify:/31cd1535-e76b-11f1-b5e7-e284dcf81adb'),(615,'storage.read:/31cd1535-e76b-11f1-b5e7-e284dcf81adb'),(615,'storage.write:/31cd1535-e76b-11f1-b5e7-e284dcf81adb'),(616,'storage.modify:/31cd177d-e76b-11f1-b5e7-e284dcf81adb'),(616,'storage.read:/31cd177d-e76b-11f1-b5e7-e284dcf81adb'),(616,'storage.write:/31cd177d-e76b-11f1-b5e7-e284dcf81adb'),(617,'storage.modify:/31cd1a2e-e76b-11f1-b5e7-e284dcf81adb'),(617,'storage.read:/31cd1a2e-e76b-11f1-b5e7-e284dcf81adb'),(617,'storage.write:/31cd1a2e-e76b-11f1-b5e7-e284dcf81adb'),(618,'storage.modify:/31cd1cd2-e76b-11f1-b5e7-e284dcf81adb'),(618,'storage.read:/31cd1cd2-e76b-11f1-b5e7-e284dcf81adb'),(618,'storage.write:/31cd1cd2-e76b-11f1-b5e7-e284dcf81adb'),(619,'storage.modify:/31cd1fa2-e76b-11f1-b5e7-e284dcf81adb'),(619,'storage.read:/31cd1fa2-e76b-11f1-b5e7-e284dcf81adb'),(619,'storage.write:/31cd1fa2-e76b-11f1-b5e7-e284dcf81adb'),(620,'storage.modify:/31cd2209-e76b-11f1-b5e7-e284dcf81adb'),(620,'storage.read:/31cd2209-e76b-11f1-b5e7-e284dcf81adb'),(620,'storage.write:/31cd2209-e76b-11f1-b5e7-e284dcf81adb'),(621,'storage.modify:/31cd245d-e76b-11f1-b5e7-e284dcf81adb'),(621,'storage.read:/31cd245d-e76b-11f1-b5e7-e284dcf81adb'),(621,'storage.write:/31cd245d-e76b-11f1-b5e7-e284dcf81adb'),(622,'storage.modify:/31cd26aa-e76b-11f1-b5e7-e284dcf81adb'),(622,'storage.read:/31cd26aa-e76b-11f1-b5e7-e284dcf81adb'),(622,'storage.write:/31cd26aa-e76b-11f1-b5e7-e284dcf81adb'),(623,'storage.modify:/31cd296d-e76b-11f1-b5e7-e284dcf81adb'),(623,'storage.read:/31cd296d-e76b-11f1-b5e7-e284dcf81adb'),(623,'storage.write:/31cd296d-e76b-11f1-b5e7-e284dcf81adb'),(624,'storage.modify:/31cd2bd7-e76b-11f1-b5e7-e284dcf81adb'),(624,'storage.read:/31cd2bd7-e76b-11f1-b5e7-e284dcf81adb'),(624,'storage.write:/31cd2bd7-e76b-11f1-b5e7-e284dcf81adb'),(625,'storage.modify:/31cd2e2f-e76b-11f1-b5e7-e284dcf81adb'),(625,'storage.read:/31cd2e2f-e76b-11f1-b5e7-e284dcf81adb'),(625,'storage.write:/31cd2e2f-e76b-11f1-b5e7-e284dcf81adb'),(626,'storage.modify:/31ce08a5-e76b-11f1-b5e7-e284dcf81adb'),(626,'storage.read:/31ce08a5-e76b-11f1-b5e7-e284dcf81adb'),(626,'storage.write:/31ce08a5-e76b-11f1-b5e7-e284dcf81adb'),(627,'storage.modify:/31ce0c2b-e76b-11f1-b5e7-e284dcf81adb'),(627,'storage.read:/31ce0c2b-e76b-11f1-b5e7-e284dcf81adb'),(627,'storage.write:/31ce0c2b-e76b-11f1-b5e7-e284dcf81adb'),(628,'storage.modify:/31ce0ec2-e76b-11f1-b5e7-e284dcf81adb'),(628,'storage.read:/31ce0ec2-e76b-11f1-b5e7-e284dcf81adb'),(628,'storage.write:/31ce0ec2-e76b-11f1-b5e7-e284dcf81adb'),(629,'storage.modify:/31ce1151-e76b-11f1-b5e7-e284dcf81adb'),(629,'storage.read:/31ce1151-e76b-11f1-b5e7-e284dcf81adb'),(629,'storage.write:/31ce1151-e76b-11f1-b5e7-e284dcf81adb'),(630,'storage.modify:/31ce13cd-e76b-11f1-b5e7-e284dcf81adb'),(630,'storage.read:/31ce13cd-e76b-11f1-b5e7-e284dcf81adb'),(630,'storage.write:/31ce13cd-e76b-11f1-b5e7-e284dcf81adb'),(631,'storage.modify:/31ce1648-e76b-11f1-b5e7-e284dcf81adb'),(631,'storage.read:/31ce1648-e76b-11f1-b5e7-e284dcf81adb'),(631,'storage.write:/31ce1648-e76b-11f1-b5e7-e284dcf81adb'),(632,'storage.modify:/31ce18bc-e76b-11f1-b5e7-e284dcf81adb'),(632,'storage.read:/31ce18bc-e76b-11f1-b5e7-e284dcf81adb'),(632,'storage.write:/31ce18bc-e76b-11f1-b5e7-e284dcf81adb'),(633,'storage.modify:/31ce1b61-e76b-11f1-b5e7-e284dcf81adb'),(633,'storage.read:/31ce1b61-e76b-11f1-b5e7-e284dcf81adb'),(633,'storage.write:/31ce1b61-e76b-11f1-b5e7-e284dcf81adb'),(634,'storage.modify:/31ce1dae-e76b-11f1-b5e7-e284dcf81adb'),(634,'storage.read:/31ce1dae-e76b-11f1-b5e7-e284dcf81adb'),(634,'storage.write:/31ce1dae-e76b-11f1-b5e7-e284dcf81adb'),(635,'storage.modify:/31ce2058-e76b-11f1-b5e7-e284dcf81adb'),(635,'storage.read:/31ce2058-e76b-11f1-b5e7-e284dcf81adb'),(635,'storage.write:/31ce2058-e76b-11f1-b5e7-e284dcf81adb'),(636,'storage.modify:/31ce230c-e76b-11f1-b5e7-e284dcf81adb'),(636,'storage.read:/31ce230c-e76b-11f1-b5e7-e284dcf81adb'),(636,'storage.write:/31ce230c-e76b-11f1-b5e7-e284dcf81adb'),(637,'storage.modify:/31ce2568-e76b-11f1-b5e7-e284dcf81adb'),(637,'storage.read:/31ce2568-e76b-11f1-b5e7-e284dcf81adb'),(637,'storage.write:/31ce2568-e76b-11f1-b5e7-e284dcf81adb'),(638,'storage.modify:/31ce27b8-e76b-11f1-b5e7-e284dcf81adb'),(638,'storage.read:/31ce27b8-e76b-11f1-b5e7-e284dcf81adb'),(638,'storage.write:/31ce27b8-e76b-11f1-b5e7-e284dcf81adb'),(639,'storage.modify:/31ce2a09-e76b-11f1-b5e7-e284dcf81adb'),(639,'storage.read:/31ce2a09-e76b-11f1-b5e7-e284dcf81adb'),(639,'storage.write:/31ce2a09-e76b-11f1-b5e7-e284dcf81adb'),(640,'storage.modify:/31ce2cc2-e76b-11f1-b5e7-e284dcf81adb'),(640,'storage.read:/31ce2cc2-e76b-11f1-b5e7-e284dcf81adb'),(640,'storage.write:/31ce2cc2-e76b-11f1-b5e7-e284dcf81adb'),(641,'storage.modify:/31ce2f30-e76b-11f1-b5e7-e284dcf81adb'),(641,'storage.read:/31ce2f30-e76b-11f1-b5e7-e284dcf81adb'),(641,'storage.write:/31ce2f30-e76b-11f1-b5e7-e284dcf81adb'),(642,'storage.modify:/31ce317c-e76b-11f1-b5e7-e284dcf81adb'),(642,'storage.read:/31ce317c-e76b-11f1-b5e7-e284dcf81adb'),(642,'storage.write:/31ce317c-e76b-11f1-b5e7-e284dcf81adb'),(643,'storage.modify:/31ce33cc-e76b-11f1-b5e7-e284dcf81adb'),(643,'storage.read:/31ce33cc-e76b-11f1-b5e7-e284dcf81adb'),(643,'storage.write:/31ce33cc-e76b-11f1-b5e7-e284dcf81adb'),(644,'storage.modify:/31ce361b-e76b-11f1-b5e7-e284dcf81adb'),(644,'storage.read:/31ce361b-e76b-11f1-b5e7-e284dcf81adb'),(644,'storage.write:/31ce361b-e76b-11f1-b5e7-e284dcf81adb'),(645,'storage.modify:/31ce3869-e76b-11f1-b5e7-e284dcf81adb'),(645,'storage.read:/31ce3869-e76b-11f1-b5e7-e284dcf81adb'),(645,'storage.write:/31ce3869-e76b-11f1-b5e7-e284dcf81adb'),(646,'storage.modify:/31cf867e-e76b-11f1-b5e7-e284dcf81adb'),(646,'storage.read:/31cf867e-e76b-11f1-b5e7-e284dcf81adb'),(646,'storage.write:/31cf867e-e76b-11f1-b5e7-e284dcf81adb'),(647,'storage.modify:/31cf899c-e76b-11f1-b5e7-e284dcf81adb'),(647,'storage.read:/31cf899c-e76b-11f1-b5e7-e284dcf81adb'),(647,'storage.write:/31cf899c-e76b-11f1-b5e7-e284dcf81adb'),(648,'storage.modify:/31cf8c60-e76b-11f1-b5e7-e284dcf81adb'),(648,'storage.read:/31cf8c60-e76b-11f1-b5e7-e284dcf81adb'),(648,'storage.write:/31cf8c60-e76b-11f1-b5e7-e284dcf81adb'),(649,'storage.modify:/31cf8e9d-e76b-11f1-b5e7-e284dcf81adb'),(649,'storage.read:/31cf8e9d-e76b-11f1-b5e7-e284dcf81adb'),(649,'storage.write:/31cf8e9d-e76b-11f1-b5e7-e284dcf81adb'),(650,'storage.modify:/31cf90b7-e76b-11f1-b5e7-e284dcf81adb'),(650,'storage.read:/31cf90b7-e76b-11f1-b5e7-e284dcf81adb'),(650,'storage.write:/31cf90b7-e76b-11f1-b5e7-e284dcf81adb'),(651,'storage.modify:/31cf92c8-e76b-11f1-b5e7-e284dcf81adb'),(651,'storage.read:/31cf92c8-e76b-11f1-b5e7-e284dcf81adb'),(651,'storage.write:/31cf92c8-e76b-11f1-b5e7-e284dcf81adb'),(652,'storage.modify:/31cf94d6-e76b-11f1-b5e7-e284dcf81adb'),(652,'storage.read:/31cf94d6-e76b-11f1-b5e7-e284dcf81adb'),(652,'storage.write:/31cf94d6-e76b-11f1-b5e7-e284dcf81adb'),(653,'storage.modify:/31cf96e7-e76b-11f1-b5e7-e284dcf81adb'),(653,'storage.read:/31cf96e7-e76b-11f1-b5e7-e284dcf81adb'),(653,'storage.write:/31cf96e7-e76b-11f1-b5e7-e284dcf81adb'),(654,'storage.modify:/31cf98fc-e76b-11f1-b5e7-e284dcf81adb'),(654,'storage.read:/31cf98fc-e76b-11f1-b5e7-e284dcf81adb'),(654,'storage.write:/31cf98fc-e76b-11f1-b5e7-e284dcf81adb'),(655,'storage.modify:/31cf9b0d-e76b-11f1-b5e7-e284dcf81adb'),(655,'storage.read:/31cf9b0d-e76b-11f1-b5e7-e284dcf81adb'),(655,'storage.write:/31cf9b0d-e76b-11f1-b5e7-e284dcf81adb'),(656,'storage.modify:/31cf9d1d-e76b-11f1-b5e7-e284dcf81adb'),(656,'storage.read:/31cf9d1d-e76b-11f1-b5e7-e284dcf81adb'),(656,'storage.write:/31cf9d1d-e76b-11f1-b5e7-e284dcf81adb'),(657,'storage.modify:/31cf9f2e-e76b-11f1-b5e7-e284dcf81adb'),(657,'storage.read:/31cf9f2e-e76b-11f1-b5e7-e284dcf81adb'),(657,'storage.write:/31cf9f2e-e76b-11f1-b5e7-e284dcf81adb'),(658,'storage.modify:/31cfa13e-e76b-11f1-b5e7-e284dcf81adb'),(658,'storage.read:/31cfa13e-e76b-11f1-b5e7-e284dcf81adb'),(658,'storage.write:/31cfa13e-e76b-11f1-b5e7-e284dcf81adb'),(659,'storage.modify:/31cfa358-e76b-11f1-b5e7-e284dcf81adb'),(659,'storage.read:/31cfa358-e76b-11f1-b5e7-e284dcf81adb'),(659,'storage.write:/31cfa358-e76b-11f1-b5e7-e284dcf81adb'),(660,'storage.modify:/31cfa56d-e76b-11f1-b5e7-e284dcf81adb'),(660,'storage.read:/31cfa56d-e76b-11f1-b5e7-e284dcf81adb'),(660,'storage.write:/31cfa56d-e76b-11f1-b5e7-e284dcf81adb'),(661,'storage.modify:/31cfa781-e76b-11f1-b5e7-e284dcf81adb'),(661,'storage.read:/31cfa781-e76b-11f1-b5e7-e284dcf81adb'),(661,'storage.write:/31cfa781-e76b-11f1-b5e7-e284dcf81adb'),(662,'storage.modify:/31cfa995-e76b-11f1-b5e7-e284dcf81adb'),(662,'storage.read:/31cfa995-e76b-11f1-b5e7-e284dcf81adb'),(662,'storage.write:/31cfa995-e76b-11f1-b5e7-e284dcf81adb'),(663,'storage.modify:/31cfabb4-e76b-11f1-b5e7-e284dcf81adb'),(663,'storage.read:/31cfabb4-e76b-11f1-b5e7-e284dcf81adb'),(663,'storage.write:/31cfabb4-e76b-11f1-b5e7-e284dcf81adb'),(664,'storage.modify:/31cfadce-e76b-11f1-b5e7-e284dcf81adb'),(664,'storage.read:/31cfadce-e76b-11f1-b5e7-e284dcf81adb'),(664,'storage.write:/31cfadce-e76b-11f1-b5e7-e284dcf81adb'),(665,'storage.modify:/31cfafe5-e76b-11f1-b5e7-e284dcf81adb'),(665,'storage.read:/31cfafe5-e76b-11f1-b5e7-e284dcf81adb'),(665,'storage.write:/31cfafe5-e76b-11f1-b5e7-e284dcf81adb'),(666,'storage.modify:/31cfb255-e76b-11f1-b5e7-e284dcf81adb'),(666,'storage.read:/31cfb255-e76b-11f1-b5e7-e284dcf81adb'),(666,'storage.write:/31cfb255-e76b-11f1-b5e7-e284dcf81adb'),(667,'storage.modify:/31cfb535-e76b-11f1-b5e7-e284dcf81adb'),(667,'storage.read:/31cfb535-e76b-11f1-b5e7-e284dcf81adb'),(667,'storage.write:/31cfb535-e76b-11f1-b5e7-e284dcf81adb'),(668,'storage.modify:/31cfb7c2-e76b-11f1-b5e7-e284dcf81adb'),(668,'storage.read:/31cfb7c2-e76b-11f1-b5e7-e284dcf81adb'),(668,'storage.write:/31cfb7c2-e76b-11f1-b5e7-e284dcf81adb'),(669,'storage.modify:/31cfba2a-e76b-11f1-b5e7-e284dcf81adb'),(669,'storage.read:/31cfba2a-e76b-11f1-b5e7-e284dcf81adb'),(669,'storage.write:/31cfba2a-e76b-11f1-b5e7-e284dcf81adb'),(670,'storage.modify:/31cfbc73-e76b-11f1-b5e7-e284dcf81adb'),(670,'storage.read:/31cfbc73-e76b-11f1-b5e7-e284dcf81adb'),(670,'storage.write:/31cfbc73-e76b-11f1-b5e7-e284dcf81adb'),(671,'storage.modify:/31cfbefd-e76b-11f1-b5e7-e284dcf81adb'),(671,'storage.read:/31cfbefd-e76b-11f1-b5e7-e284dcf81adb'),(671,'storage.write:/31cfbefd-e76b-11f1-b5e7-e284dcf81adb'),(672,'storage.modify:/31cfc231-e76b-11f1-b5e7-e284dcf81adb'),(672,'storage.read:/31cfc231-e76b-11f1-b5e7-e284dcf81adb'),(672,'storage.write:/31cfc231-e76b-11f1-b5e7-e284dcf81adb'),(673,'storage.modify:/31cfc497-e76b-11f1-b5e7-e284dcf81adb'),(673,'storage.read:/31cfc497-e76b-11f1-b5e7-e284dcf81adb'),(673,'storage.write:/31cfc497-e76b-11f1-b5e7-e284dcf81adb'),(674,'storage.modify:/31cfc6e4-e76b-11f1-b5e7-e284dcf81adb'),(674,'storage.read:/31cfc6e4-e76b-11f1-b5e7-e284dcf81adb'),(674,'storage.write:/31cfc6e4-e76b-11f1-b5e7-e284dcf81adb'),(675,'storage.modify:/31cfca27-e76b-11f1-b5e7-e284dcf81adb'),(675,'storage.read:/31cfca27-e76b-11f1-b5e7-e284dcf81adb'),(675,'storage.write:/31cfca27-e76b-11f1-b5e7-e284dcf81adb'),(676,'storage.modify:/31cfcc92-e76b-11f1-b5e7-e284dcf81adb'),(676,'storage.read:/31cfcc92-e76b-11f1-b5e7-e284dcf81adb'),(676,'storage.write:/31cfcc92-e76b-11f1-b5e7-e284dcf81adb'),(677,'storage.modify:/31d26d0e-e76b-11f1-b5e7-e284dcf81adb'),(677,'storage.read:/31d26d0e-e76b-11f1-b5e7-e284dcf81adb'),(677,'storage.write:/31d26d0e-e76b-11f1-b5e7-e284dcf81adb'),(678,'storage.modify:/31d27358-e76b-11f1-b5e7-e284dcf81adb'),(678,'storage.read:/31d27358-e76b-11f1-b5e7-e284dcf81adb'),(678,'storage.write:/31d27358-e76b-11f1-b5e7-e284dcf81adb'),(679,'storage.modify:/31d27618-e76b-11f1-b5e7-e284dcf81adb'),(679,'storage.read:/31d27618-e76b-11f1-b5e7-e284dcf81adb'),(679,'storage.write:/31d27618-e76b-11f1-b5e7-e284dcf81adb'),(680,'storage.modify:/31d2787d-e76b-11f1-b5e7-e284dcf81adb'),(680,'storage.read:/31d2787d-e76b-11f1-b5e7-e284dcf81adb'),(680,'storage.write:/31d2787d-e76b-11f1-b5e7-e284dcf81adb'),(681,'storage.modify:/31d27b28-e76b-11f1-b5e7-e284dcf81adb'),(681,'storage.read:/31d27b28-e76b-11f1-b5e7-e284dcf81adb'),(681,'storage.write:/31d27b28-e76b-11f1-b5e7-e284dcf81adb'),(682,'storage.modify:/31d27e70-e76b-11f1-b5e7-e284dcf81adb'),(682,'storage.read:/31d27e70-e76b-11f1-b5e7-e284dcf81adb'),(682,'storage.write:/31d27e70-e76b-11f1-b5e7-e284dcf81adb'),(683,'storage.modify:/31d280de-e76b-11f1-b5e7-e284dcf81adb'),(683,'storage.read:/31d280de-e76b-11f1-b5e7-e284dcf81adb'),(683,'storage.write:/31d280de-e76b-11f1-b5e7-e284dcf81adb'),(684,'storage.modify:/31d28330-e76b-11f1-b5e7-e284dcf81adb'),(684,'storage.read:/31d28330-e76b-11f1-b5e7-e284dcf81adb'),(684,'storage.write:/31d28330-e76b-11f1-b5e7-e284dcf81adb'),(685,'storage.modify:/31d3fd1e-e76b-11f1-b5e7-e284dcf81adb'),(685,'storage.read:/31d3fd1e-e76b-11f1-b5e7-e284dcf81adb'),(685,'storage.write:/31d3fd1e-e76b-11f1-b5e7-e284dcf81adb'),(686,'storage.modify:/31d4015f-e76b-11f1-b5e7-e284dcf81adb'),(686,'storage.read:/31d4015f-e76b-11f1-b5e7-e284dcf81adb'),(686,'storage.write:/31d4015f-e76b-11f1-b5e7-e284dcf81adb'),(687,'storage.modify:/31d403ea-e76b-11f1-b5e7-e284dcf81adb'),(687,'storage.read:/31d403ea-e76b-11f1-b5e7-e284dcf81adb'),(687,'storage.write:/31d403ea-e76b-11f1-b5e7-e284dcf81adb'),(688,'storage.modify:/31d40649-e76b-11f1-b5e7-e284dcf81adb'),(688,'storage.read:/31d40649-e76b-11f1-b5e7-e284dcf81adb'),(688,'storage.write:/31d40649-e76b-11f1-b5e7-e284dcf81adb'),(689,'storage.modify:/31d408a3-e76b-11f1-b5e7-e284dcf81adb'),(689,'storage.read:/31d408a3-e76b-11f1-b5e7-e284dcf81adb'),(689,'storage.write:/31d408a3-e76b-11f1-b5e7-e284dcf81adb'),(690,'storage.modify:/31d40b24-e76b-11f1-b5e7-e284dcf81adb'),(690,'storage.read:/31d40b24-e76b-11f1-b5e7-e284dcf81adb'),(690,'storage.write:/31d40b24-e76b-11f1-b5e7-e284dcf81adb'),(691,'storage.modify:/31d40d7d-e76b-11f1-b5e7-e284dcf81adb'),(691,'storage.read:/31d40d7d-e76b-11f1-b5e7-e284dcf81adb'),(691,'storage.write:/31d40d7d-e76b-11f1-b5e7-e284dcf81adb'),(692,'storage.modify:/31d40fdb-e76b-11f1-b5e7-e284dcf81adb'),(692,'storage.read:/31d40fdb-e76b-11f1-b5e7-e284dcf81adb'),(692,'storage.write:/31d40fdb-e76b-11f1-b5e7-e284dcf81adb'),(693,'storage.modify:/31d4123b-e76b-11f1-b5e7-e284dcf81adb'),(693,'storage.read:/31d4123b-e76b-11f1-b5e7-e284dcf81adb'),(693,'storage.write:/31d4123b-e76b-11f1-b5e7-e284dcf81adb'),(694,'storage.modify:/31d41490-e76b-11f1-b5e7-e284dcf81adb'),(694,'storage.read:/31d41490-e76b-11f1-b5e7-e284dcf81adb'),(694,'storage.write:/31d41490-e76b-11f1-b5e7-e284dcf81adb'),(695,'storage.modify:/31d416e8-e76b-11f1-b5e7-e284dcf81adb'),(695,'storage.read:/31d416e8-e76b-11f1-b5e7-e284dcf81adb'),(695,'storage.write:/31d416e8-e76b-11f1-b5e7-e284dcf81adb'),(696,'storage.modify:/31d4193c-e76b-11f1-b5e7-e284dcf81adb'),(696,'storage.read:/31d4193c-e76b-11f1-b5e7-e284dcf81adb'),(696,'storage.write:/31d4193c-e76b-11f1-b5e7-e284dcf81adb'),(697,'storage.modify:/31d41b92-e76b-11f1-b5e7-e284dcf81adb'),(697,'storage.read:/31d41b92-e76b-11f1-b5e7-e284dcf81adb'),(697,'storage.write:/31d41b92-e76b-11f1-b5e7-e284dcf81adb'),(698,'storage.modify:/31d41de8-e76b-11f1-b5e7-e284dcf81adb'),(698,'storage.read:/31d41de8-e76b-11f1-b5e7-e284dcf81adb'),(698,'storage.write:/31d41de8-e76b-11f1-b5e7-e284dcf81adb'),(699,'storage.modify:/31d420a7-e76b-11f1-b5e7-e284dcf81adb'),(699,'storage.read:/31d420a7-e76b-11f1-b5e7-e284dcf81adb'),(699,'storage.write:/31d420a7-e76b-11f1-b5e7-e284dcf81adb'),(700,'storage.modify:/31d42304-e76b-11f1-b5e7-e284dcf81adb'),(700,'storage.read:/31d42304-e76b-11f1-b5e7-e284dcf81adb'),(700,'storage.write:/31d42304-e76b-11f1-b5e7-e284dcf81adb'),(701,'storage.modify:/31d4256b-e76b-11f1-b5e7-e284dcf81adb'),(701,'storage.read:/31d4256b-e76b-11f1-b5e7-e284dcf81adb'),(701,'storage.write:/31d4256b-e76b-11f1-b5e7-e284dcf81adb'),(702,'storage.modify:/31d427c3-e76b-11f1-b5e7-e284dcf81adb'),(702,'storage.read:/31d427c3-e76b-11f1-b5e7-e284dcf81adb'),(702,'storage.write:/31d427c3-e76b-11f1-b5e7-e284dcf81adb'),(703,'storage.modify:/31d42a16-e76b-11f1-b5e7-e284dcf81adb'),(703,'storage.read:/31d42a16-e76b-11f1-b5e7-e284dcf81adb'),(703,'storage.write:/31d42a16-e76b-11f1-b5e7-e284dcf81adb'),(704,'storage.modify:/31d42c6d-e76b-11f1-b5e7-e284dcf81adb'),(704,'storage.read:/31d42c6d-e76b-11f1-b5e7-e284dcf81adb'),(704,'storage.write:/31d42c6d-e76b-11f1-b5e7-e284dcf81adb'),(705,'storage.modify:/31d42ec1-e76b-11f1-b5e7-e284dcf81adb'),(705,'storage.read:/31d42ec1-e76b-11f1-b5e7-e284dcf81adb'),(705,'storage.write:/31d42ec1-e76b-11f1-b5e7-e284dcf81adb'),(706,'storage.modify:/31d43113-e76b-11f1-b5e7-e284dcf81adb'),(706,'storage.read:/31d43113-e76b-11f1-b5e7-e284dcf81adb'),(706,'storage.write:/31d43113-e76b-11f1-b5e7-e284dcf81adb'),(707,'storage.modify:/31d4335e-e76b-11f1-b5e7-e284dcf81adb'),(707,'storage.read:/31d4335e-e76b-11f1-b5e7-e284dcf81adb'),(707,'storage.write:/31d4335e-e76b-11f1-b5e7-e284dcf81adb'),(708,'storage.modify:/31d435a8-e76b-11f1-b5e7-e284dcf81adb'),(708,'storage.read:/31d435a8-e76b-11f1-b5e7-e284dcf81adb'),(708,'storage.write:/31d435a8-e76b-11f1-b5e7-e284dcf81adb'),(709,'storage.modify:/31d437f0-e76b-11f1-b5e7-e284dcf81adb'),(709,'storage.read:/31d437f0-e76b-11f1-b5e7-e284dcf81adb'),(709,'storage.write:/31d437f0-e76b-11f1-b5e7-e284dcf81adb'),(710,'storage.modify:/31d43a3a-e76b-11f1-b5e7-e284dcf81adb'),(710,'storage.read:/31d43a3a-e76b-11f1-b5e7-e284dcf81adb'),(710,'storage.write:/31d43a3a-e76b-11f1-b5e7-e284dcf81adb'),(711,'storage.modify:/31d43c81-e76b-11f1-b5e7-e284dcf81adb'),(711,'storage.read:/31d43c81-e76b-11f1-b5e7-e284dcf81adb'),(711,'storage.write:/31d43c81-e76b-11f1-b5e7-e284dcf81adb'),(712,'storage.modify:/31d43ec6-e76b-11f1-b5e7-e284dcf81adb'),(712,'storage.read:/31d43ec6-e76b-11f1-b5e7-e284dcf81adb'),(712,'storage.write:/31d43ec6-e76b-11f1-b5e7-e284dcf81adb'),(713,'storage.modify:/31d44110-e76b-11f1-b5e7-e284dcf81adb'),(713,'storage.read:/31d44110-e76b-11f1-b5e7-e284dcf81adb'),(713,'storage.write:/31d44110-e76b-11f1-b5e7-e284dcf81adb'),(714,'storage.modify:/31d4435a-e76b-11f1-b5e7-e284dcf81adb'),(714,'storage.read:/31d4435a-e76b-11f1-b5e7-e284dcf81adb'),(714,'storage.write:/31d4435a-e76b-11f1-b5e7-e284dcf81adb'),(715,'storage.modify:/31d445c6-e76b-11f1-b5e7-e284dcf81adb'),(715,'storage.read:/31d445c6-e76b-11f1-b5e7-e284dcf81adb'),(715,'storage.write:/31d445c6-e76b-11f1-b5e7-e284dcf81adb'),(716,'storage.modify:/31d44827-e76b-11f1-b5e7-e284dcf81adb'),(716,'storage.read:/31d44827-e76b-11f1-b5e7-e284dcf81adb'),(716,'storage.write:/31d44827-e76b-11f1-b5e7-e284dcf81adb'),(717,'storage.modify:/31d44a73-e76b-11f1-b5e7-e284dcf81adb'),(717,'storage.read:/31d44a73-e76b-11f1-b5e7-e284dcf81adb'),(717,'storage.write:/31d44a73-e76b-11f1-b5e7-e284dcf81adb'),(718,'storage.modify:/31d44d31-e76b-11f1-b5e7-e284dcf81adb'),(718,'storage.read:/31d44d31-e76b-11f1-b5e7-e284dcf81adb'),(718,'storage.write:/31d44d31-e76b-11f1-b5e7-e284dcf81adb'),(719,'storage.modify:/31d4507d-e76b-11f1-b5e7-e284dcf81adb'),(719,'storage.read:/31d4507d-e76b-11f1-b5e7-e284dcf81adb'),(719,'storage.write:/31d4507d-e76b-11f1-b5e7-e284dcf81adb'),(720,'storage.modify:/31d452f9-e76b-11f1-b5e7-e284dcf81adb'),(720,'storage.read:/31d452f9-e76b-11f1-b5e7-e284dcf81adb'),(720,'storage.write:/31d452f9-e76b-11f1-b5e7-e284dcf81adb'),(721,'storage.modify:/31d45549-e76b-11f1-b5e7-e284dcf81adb'),(721,'storage.read:/31d45549-e76b-11f1-b5e7-e284dcf81adb'),(721,'storage.write:/31d45549-e76b-11f1-b5e7-e284dcf81adb'),(722,'storage.modify:/31d457a4-e76b-11f1-b5e7-e284dcf81adb'),(722,'storage.read:/31d457a4-e76b-11f1-b5e7-e284dcf81adb'),(722,'storage.write:/31d457a4-e76b-11f1-b5e7-e284dcf81adb'),(723,'storage.modify:/31d45a03-e76b-11f1-b5e7-e284dcf81adb'),(723,'storage.read:/31d45a03-e76b-11f1-b5e7-e284dcf81adb'),(723,'storage.write:/31d45a03-e76b-11f1-b5e7-e284dcf81adb'),(724,'storage.modify:/31d70294-e76b-11f1-b5e7-e284dcf81adb'),(724,'storage.read:/31d70294-e76b-11f1-b5e7-e284dcf81adb'),(724,'storage.write:/31d70294-e76b-11f1-b5e7-e284dcf81adb'),(725,'storage.modify:/31d70662-e76b-11f1-b5e7-e284dcf81adb'),(725,'storage.read:/31d70662-e76b-11f1-b5e7-e284dcf81adb'),(725,'storage.write:/31d70662-e76b-11f1-b5e7-e284dcf81adb'),(726,'storage.modify:/31d708eb-e76b-11f1-b5e7-e284dcf81adb'),(726,'storage.read:/31d708eb-e76b-11f1-b5e7-e284dcf81adb'),(726,'storage.write:/31d708eb-e76b-11f1-b5e7-e284dcf81adb'),(727,'storage.modify:/31d70b4d-e76b-11f1-b5e7-e284dcf81adb'),(727,'storage.read:/31d70b4d-e76b-11f1-b5e7-e284dcf81adb'),(727,'storage.write:/31d70b4d-e76b-11f1-b5e7-e284dcf81adb'),(728,'storage.modify:/31d70d9f-e76b-11f1-b5e7-e284dcf81adb'),(728,'storage.read:/31d70d9f-e76b-11f1-b5e7-e284dcf81adb'),(728,'storage.write:/31d70d9f-e76b-11f1-b5e7-e284dcf81adb'),(729,'storage.modify:/31d71002-e76b-11f1-b5e7-e284dcf81adb'),(729,'storage.read:/31d71002-e76b-11f1-b5e7-e284dcf81adb'),(729,'storage.write:/31d71002-e76b-11f1-b5e7-e284dcf81adb'),(730,'storage.modify:/31d7124b-e76b-11f1-b5e7-e284dcf81adb'),(730,'storage.read:/31d7124b-e76b-11f1-b5e7-e284dcf81adb'),(730,'storage.write:/31d7124b-e76b-11f1-b5e7-e284dcf81adb'),(731,'storage.modify:/31d71492-e76b-11f1-b5e7-e284dcf81adb'),(731,'storage.read:/31d71492-e76b-11f1-b5e7-e284dcf81adb'),(731,'storage.write:/31d71492-e76b-11f1-b5e7-e284dcf81adb'),(732,'storage.modify:/31d716e1-e76b-11f1-b5e7-e284dcf81adb'),(732,'storage.read:/31d716e1-e76b-11f1-b5e7-e284dcf81adb'),(732,'storage.write:/31d716e1-e76b-11f1-b5e7-e284dcf81adb'),(733,'storage.modify:/31d71927-e76b-11f1-b5e7-e284dcf81adb'),(733,'storage.read:/31d71927-e76b-11f1-b5e7-e284dcf81adb'),(733,'storage.write:/31d71927-e76b-11f1-b5e7-e284dcf81adb'),(734,'storage.modify:/31d71b71-e76b-11f1-b5e7-e284dcf81adb'),(734,'storage.read:/31d71b71-e76b-11f1-b5e7-e284dcf81adb'),(734,'storage.write:/31d71b71-e76b-11f1-b5e7-e284dcf81adb'),(735,'storage.modify:/31d71dd5-e76b-11f1-b5e7-e284dcf81adb'),(735,'storage.read:/31d71dd5-e76b-11f1-b5e7-e284dcf81adb'),(735,'storage.write:/31d71dd5-e76b-11f1-b5e7-e284dcf81adb'),(736,'storage.modify:/31d720a6-e76b-11f1-b5e7-e284dcf81adb'),(736,'storage.read:/31d720a6-e76b-11f1-b5e7-e284dcf81adb'),(736,'storage.write:/31d720a6-e76b-11f1-b5e7-e284dcf81adb'),(737,'storage.modify:/31d72303-e76b-11f1-b5e7-e284dcf81adb'),(737,'storage.read:/31d72303-e76b-11f1-b5e7-e284dcf81adb'),(737,'storage.write:/31d72303-e76b-11f1-b5e7-e284dcf81adb'),(738,'storage.modify:/31d72550-e76b-11f1-b5e7-e284dcf81adb'),(738,'storage.read:/31d72550-e76b-11f1-b5e7-e284dcf81adb'),(738,'storage.write:/31d72550-e76b-11f1-b5e7-e284dcf81adb'),(739,'storage.modify:/31d72860-e76b-11f1-b5e7-e284dcf81adb'),(739,'storage.read:/31d72860-e76b-11f1-b5e7-e284dcf81adb'),(739,'storage.write:/31d72860-e76b-11f1-b5e7-e284dcf81adb'),(740,'storage.modify:/31d72ad6-e76b-11f1-b5e7-e284dcf81adb'),(740,'storage.read:/31d72ad6-e76b-11f1-b5e7-e284dcf81adb'),(740,'storage.write:/31d72ad6-e76b-11f1-b5e7-e284dcf81adb'),(741,'storage.modify:/31d72da7-e76b-11f1-b5e7-e284dcf81adb'),(741,'storage.read:/31d72da7-e76b-11f1-b5e7-e284dcf81adb'),(741,'storage.write:/31d72da7-e76b-11f1-b5e7-e284dcf81adb'),(742,'storage.modify:/31d73003-e76b-11f1-b5e7-e284dcf81adb'),(742,'storage.read:/31d73003-e76b-11f1-b5e7-e284dcf81adb'),(742,'storage.write:/31d73003-e76b-11f1-b5e7-e284dcf81adb'),(743,'storage.modify:/31d7324c-e76b-11f1-b5e7-e284dcf81adb'),(743,'storage.read:/31d7324c-e76b-11f1-b5e7-e284dcf81adb'),(743,'storage.write:/31d7324c-e76b-11f1-b5e7-e284dcf81adb'),(744,'storage.modify:/31d88168-e76b-11f1-b5e7-e284dcf81adb'),(744,'storage.read:/31d88168-e76b-11f1-b5e7-e284dcf81adb'),(744,'storage.write:/31d88168-e76b-11f1-b5e7-e284dcf81adb'),(745,'storage.modify:/31d88602-e76b-11f1-b5e7-e284dcf81adb'),(745,'storage.read:/31d88602-e76b-11f1-b5e7-e284dcf81adb'),(745,'storage.write:/31d88602-e76b-11f1-b5e7-e284dcf81adb'),(746,'storage.modify:/31d889fe-e76b-11f1-b5e7-e284dcf81adb'),(746,'storage.read:/31d889fe-e76b-11f1-b5e7-e284dcf81adb'),(746,'storage.write:/31d889fe-e76b-11f1-b5e7-e284dcf81adb'),(747,'storage.modify:/31d88de8-e76b-11f1-b5e7-e284dcf81adb'),(747,'storage.read:/31d88de8-e76b-11f1-b5e7-e284dcf81adb'),(747,'storage.write:/31d88de8-e76b-11f1-b5e7-e284dcf81adb'),(748,'storage.modify:/31d890d1-e76b-11f1-b5e7-e284dcf81adb'),(748,'storage.read:/31d890d1-e76b-11f1-b5e7-e284dcf81adb'),(748,'storage.write:/31d890d1-e76b-11f1-b5e7-e284dcf81adb'),(749,'storage.modify:/31d8936a-e76b-11f1-b5e7-e284dcf81adb'),(749,'storage.read:/31d8936a-e76b-11f1-b5e7-e284dcf81adb'),(749,'storage.write:/31d8936a-e76b-11f1-b5e7-e284dcf81adb'),(750,'storage.modify:/31d8972e-e76b-11f1-b5e7-e284dcf81adb'),(750,'storage.read:/31d8972e-e76b-11f1-b5e7-e284dcf81adb'),(750,'storage.write:/31d8972e-e76b-11f1-b5e7-e284dcf81adb'),(751,'storage.modify:/31d899cb-e76b-11f1-b5e7-e284dcf81adb'),(751,'storage.read:/31d899cb-e76b-11f1-b5e7-e284dcf81adb'),(751,'storage.write:/31d899cb-e76b-11f1-b5e7-e284dcf81adb'),(752,'storage.modify:/31db7921-e76b-11f1-b5e7-e284dcf81adb'),(752,'storage.read:/31db7921-e76b-11f1-b5e7-e284dcf81adb'),(752,'storage.write:/31db7921-e76b-11f1-b5e7-e284dcf81adb'),(753,'storage.modify:/31db7f3e-e76b-11f1-b5e7-e284dcf81adb'),(753,'storage.read:/31db7f3e-e76b-11f1-b5e7-e284dcf81adb'),(753,'storage.write:/31db7f3e-e76b-11f1-b5e7-e284dcf81adb'),(754,'storage.modify:/31db8263-e76b-11f1-b5e7-e284dcf81adb'),(754,'storage.read:/31db8263-e76b-11f1-b5e7-e284dcf81adb'),(754,'storage.write:/31db8263-e76b-11f1-b5e7-e284dcf81adb'),(755,'storage.modify:/31dc418b-e76b-11f1-b5e7-e284dcf81adb'),(755,'storage.read:/31dc418b-e76b-11f1-b5e7-e284dcf81adb'),(755,'storage.write:/31dc418b-e76b-11f1-b5e7-e284dcf81adb'),(756,'storage.modify:/31dc45af-e76b-11f1-b5e7-e284dcf81adb'),(756,'storage.read:/31dc45af-e76b-11f1-b5e7-e284dcf81adb'),(756,'storage.write:/31dc45af-e76b-11f1-b5e7-e284dcf81adb'),(757,'storage.modify:/31dc4826-e76b-11f1-b5e7-e284dcf81adb'),(757,'storage.read:/31dc4826-e76b-11f1-b5e7-e284dcf81adb'),(757,'storage.write:/31dc4826-e76b-11f1-b5e7-e284dcf81adb'),(758,'storage.modify:/31dc4a8d-e76b-11f1-b5e7-e284dcf81adb'),(758,'storage.read:/31dc4a8d-e76b-11f1-b5e7-e284dcf81adb'),(758,'storage.write:/31dc4a8d-e76b-11f1-b5e7-e284dcf81adb'),(759,'storage.modify:/31dc4cea-e76b-11f1-b5e7-e284dcf81adb'),(759,'storage.read:/31dc4cea-e76b-11f1-b5e7-e284dcf81adb'),(759,'storage.write:/31dc4cea-e76b-11f1-b5e7-e284dcf81adb'),(760,'storage.modify:/31dc4f3e-e76b-11f1-b5e7-e284dcf81adb'),(760,'storage.read:/31dc4f3e-e76b-11f1-b5e7-e284dcf81adb'),(760,'storage.write:/31dc4f3e-e76b-11f1-b5e7-e284dcf81adb'),(761,'storage.modify:/31dc51d1-e76b-11f1-b5e7-e284dcf81adb'),(761,'storage.read:/31dc51d1-e76b-11f1-b5e7-e284dcf81adb'),(761,'storage.write:/31dc51d1-e76b-11f1-b5e7-e284dcf81adb'),(762,'storage.modify:/31dc548a-e76b-11f1-b5e7-e284dcf81adb'),(762,'storage.read:/31dc548a-e76b-11f1-b5e7-e284dcf81adb'),(762,'storage.write:/31dc548a-e76b-11f1-b5e7-e284dcf81adb'),(763,'storage.modify:/31dc56e2-e76b-11f1-b5e7-e284dcf81adb'),(763,'storage.read:/31dc56e2-e76b-11f1-b5e7-e284dcf81adb'),(763,'storage.write:/31dc56e2-e76b-11f1-b5e7-e284dcf81adb'),(764,'storage.modify:/31dc5940-e76b-11f1-b5e7-e284dcf81adb'),(764,'storage.read:/31dc5940-e76b-11f1-b5e7-e284dcf81adb'),(764,'storage.write:/31dc5940-e76b-11f1-b5e7-e284dcf81adb'),(765,'storage.modify:/31dc5b90-e76b-11f1-b5e7-e284dcf81adb'),(765,'storage.read:/31dc5b90-e76b-11f1-b5e7-e284dcf81adb'),(765,'storage.write:/31dc5b90-e76b-11f1-b5e7-e284dcf81adb'),(766,'storage.modify:/31dc5e4c-e76b-11f1-b5e7-e284dcf81adb'),(766,'storage.read:/31dc5e4c-e76b-11f1-b5e7-e284dcf81adb'),(766,'storage.write:/31dc5e4c-e76b-11f1-b5e7-e284dcf81adb'),(767,'storage.modify:/31dc609a-e76b-11f1-b5e7-e284dcf81adb'),(767,'storage.read:/31dc609a-e76b-11f1-b5e7-e284dcf81adb'),(767,'storage.write:/31dc609a-e76b-11f1-b5e7-e284dcf81adb'),(768,'storage.modify:/31dc62e2-e76b-11f1-b5e7-e284dcf81adb'),(768,'storage.read:/31dc62e2-e76b-11f1-b5e7-e284dcf81adb'),(768,'storage.write:/31dc62e2-e76b-11f1-b5e7-e284dcf81adb'),(769,'storage.modify:/31dc6536-e76b-11f1-b5e7-e284dcf81adb'),(769,'storage.read:/31dc6536-e76b-11f1-b5e7-e284dcf81adb'),(769,'storage.write:/31dc6536-e76b-11f1-b5e7-e284dcf81adb'),(770,'storage.modify:/31dc67d3-e76b-11f1-b5e7-e284dcf81adb'),(770,'storage.read:/31dc67d3-e76b-11f1-b5e7-e284dcf81adb'),(770,'storage.write:/31dc67d3-e76b-11f1-b5e7-e284dcf81adb'),(771,'storage.modify:/31dc6a24-e76b-11f1-b5e7-e284dcf81adb'),(771,'storage.read:/31dc6a24-e76b-11f1-b5e7-e284dcf81adb'),(771,'storage.write:/31dc6a24-e76b-11f1-b5e7-e284dcf81adb'),(772,'storage.modify:/31dc6c78-e76b-11f1-b5e7-e284dcf81adb'),(772,'storage.read:/31dc6c78-e76b-11f1-b5e7-e284dcf81adb'),(772,'storage.write:/31dc6c78-e76b-11f1-b5e7-e284dcf81adb'),(773,'storage.modify:/31dc6ec3-e76b-11f1-b5e7-e284dcf81adb'),(773,'storage.read:/31dc6ec3-e76b-11f1-b5e7-e284dcf81adb'),(773,'storage.write:/31dc6ec3-e76b-11f1-b5e7-e284dcf81adb'),(774,'storage.modify:/31dc7105-e76b-11f1-b5e7-e284dcf81adb'),(774,'storage.read:/31dc7105-e76b-11f1-b5e7-e284dcf81adb'),(774,'storage.write:/31dc7105-e76b-11f1-b5e7-e284dcf81adb'),(775,'storage.modify:/31dc734b-e76b-11f1-b5e7-e284dcf81adb'),(775,'storage.read:/31dc734b-e76b-11f1-b5e7-e284dcf81adb'),(775,'storage.write:/31dc734b-e76b-11f1-b5e7-e284dcf81adb'),(776,'storage.modify:/31dc7590-e76b-11f1-b5e7-e284dcf81adb'),(776,'storage.read:/31dc7590-e76b-11f1-b5e7-e284dcf81adb'),(776,'storage.write:/31dc7590-e76b-11f1-b5e7-e284dcf81adb'),(777,'storage.modify:/31dc77db-e76b-11f1-b5e7-e284dcf81adb'),(777,'storage.read:/31dc77db-e76b-11f1-b5e7-e284dcf81adb'),(777,'storage.write:/31dc77db-e76b-11f1-b5e7-e284dcf81adb'),(778,'storage.modify:/31dc7a23-e76b-11f1-b5e7-e284dcf81adb'),(778,'storage.read:/31dc7a23-e76b-11f1-b5e7-e284dcf81adb'),(778,'storage.write:/31dc7a23-e76b-11f1-b5e7-e284dcf81adb'),(779,'storage.modify:/31ddb961-e76b-11f1-b5e7-e284dcf81adb'),(779,'storage.read:/31ddb961-e76b-11f1-b5e7-e284dcf81adb'),(779,'storage.write:/31ddb961-e76b-11f1-b5e7-e284dcf81adb'),(780,'storage.modify:/31ddbd3d-e76b-11f1-b5e7-e284dcf81adb'),(780,'storage.read:/31ddbd3d-e76b-11f1-b5e7-e284dcf81adb'),(780,'storage.write:/31ddbd3d-e76b-11f1-b5e7-e284dcf81adb'),(781,'storage.modify:/31ddbfd2-e76b-11f1-b5e7-e284dcf81adb'),(781,'storage.read:/31ddbfd2-e76b-11f1-b5e7-e284dcf81adb'),(781,'storage.write:/31ddbfd2-e76b-11f1-b5e7-e284dcf81adb'),(782,'storage.modify:/31ddc24e-e76b-11f1-b5e7-e284dcf81adb'),(782,'storage.read:/31ddc24e-e76b-11f1-b5e7-e284dcf81adb'),(782,'storage.write:/31ddc24e-e76b-11f1-b5e7-e284dcf81adb'),(783,'storage.modify:/31ddc4c9-e76b-11f1-b5e7-e284dcf81adb'),(783,'storage.read:/31ddc4c9-e76b-11f1-b5e7-e284dcf81adb'),(783,'storage.write:/31ddc4c9-e76b-11f1-b5e7-e284dcf81adb'),(784,'storage.modify:/31ddc779-e76b-11f1-b5e7-e284dcf81adb'),(784,'storage.read:/31ddc779-e76b-11f1-b5e7-e284dcf81adb'),(784,'storage.write:/31ddc779-e76b-11f1-b5e7-e284dcf81adb'),(785,'storage.modify:/31ddca1e-e76b-11f1-b5e7-e284dcf81adb'),(785,'storage.read:/31ddca1e-e76b-11f1-b5e7-e284dcf81adb'),(785,'storage.write:/31ddca1e-e76b-11f1-b5e7-e284dcf81adb'),(786,'storage.modify:/31ddcc8e-e76b-11f1-b5e7-e284dcf81adb'),(786,'storage.read:/31ddcc8e-e76b-11f1-b5e7-e284dcf81adb'),(786,'storage.write:/31ddcc8e-e76b-11f1-b5e7-e284dcf81adb'),(787,'storage.modify:/31ddcf0d-e76b-11f1-b5e7-e284dcf81adb'),(787,'storage.read:/31ddcf0d-e76b-11f1-b5e7-e284dcf81adb'),(787,'storage.write:/31ddcf0d-e76b-11f1-b5e7-e284dcf81adb'),(788,'storage.modify:/31ddd17d-e76b-11f1-b5e7-e284dcf81adb'),(788,'storage.read:/31ddd17d-e76b-11f1-b5e7-e284dcf81adb'),(788,'storage.write:/31ddd17d-e76b-11f1-b5e7-e284dcf81adb'),(789,'storage.modify:/31ddd3f3-e76b-11f1-b5e7-e284dcf81adb'),(789,'storage.read:/31ddd3f3-e76b-11f1-b5e7-e284dcf81adb'),(789,'storage.write:/31ddd3f3-e76b-11f1-b5e7-e284dcf81adb'),(790,'storage.modify:/31ddd63c-e76b-11f1-b5e7-e284dcf81adb'),(790,'storage.read:/31ddd63c-e76b-11f1-b5e7-e284dcf81adb'),(790,'storage.write:/31ddd63c-e76b-11f1-b5e7-e284dcf81adb'),(791,'storage.modify:/31ddd887-e76b-11f1-b5e7-e284dcf81adb'),(791,'storage.read:/31ddd887-e76b-11f1-b5e7-e284dcf81adb'),(791,'storage.write:/31ddd887-e76b-11f1-b5e7-e284dcf81adb'),(792,'storage.modify:/31dddad1-e76b-11f1-b5e7-e284dcf81adb'),(792,'storage.read:/31dddad1-e76b-11f1-b5e7-e284dcf81adb'),(792,'storage.write:/31dddad1-e76b-11f1-b5e7-e284dcf81adb'),(793,'storage.modify:/31dddd23-e76b-11f1-b5e7-e284dcf81adb'),(793,'storage.read:/31dddd23-e76b-11f1-b5e7-e284dcf81adb'),(793,'storage.write:/31dddd23-e76b-11f1-b5e7-e284dcf81adb'),(794,'storage.modify:/31dddf75-e76b-11f1-b5e7-e284dcf81adb'),(794,'storage.read:/31dddf75-e76b-11f1-b5e7-e284dcf81adb'),(794,'storage.write:/31dddf75-e76b-11f1-b5e7-e284dcf81adb'),(795,'storage.modify:/31dde1c7-e76b-11f1-b5e7-e284dcf81adb'),(795,'storage.read:/31dde1c7-e76b-11f1-b5e7-e284dcf81adb'),(795,'storage.write:/31dde1c7-e76b-11f1-b5e7-e284dcf81adb'),(796,'storage.modify:/31dde45a-e76b-11f1-b5e7-e284dcf81adb'),(796,'storage.read:/31dde45a-e76b-11f1-b5e7-e284dcf81adb'),(796,'storage.write:/31dde45a-e76b-11f1-b5e7-e284dcf81adb'),(797,'storage.modify:/31dde6b2-e76b-11f1-b5e7-e284dcf81adb'),(797,'storage.read:/31dde6b2-e76b-11f1-b5e7-e284dcf81adb'),(797,'storage.write:/31dde6b2-e76b-11f1-b5e7-e284dcf81adb'),(798,'storage.modify:/31dde902-e76b-11f1-b5e7-e284dcf81adb'),(798,'storage.read:/31dde902-e76b-11f1-b5e7-e284dcf81adb'),(798,'storage.write:/31dde902-e76b-11f1-b5e7-e284dcf81adb'),(799,'storage.modify:/31ddeb55-e76b-11f1-b5e7-e284dcf81adb'),(799,'storage.read:/31ddeb55-e76b-11f1-b5e7-e284dcf81adb'),(799,'storage.write:/31ddeb55-e76b-11f1-b5e7-e284dcf81adb'),(800,'storage.modify:/31ddeda8-e76b-11f1-b5e7-e284dcf81adb'),(800,'storage.read:/31ddeda8-e76b-11f1-b5e7-e284dcf81adb'),(800,'storage.write:/31ddeda8-e76b-11f1-b5e7-e284dcf81adb'),(801,'storage.modify:/31ddf02c-e76b-11f1-b5e7-e284dcf81adb'),(801,'storage.read:/31ddf02c-e76b-11f1-b5e7-e284dcf81adb'),(801,'storage.write:/31ddf02c-e76b-11f1-b5e7-e284dcf81adb'),(802,'storage.modify:/31ddf28e-e76b-11f1-b5e7-e284dcf81adb'),(802,'storage.read:/31ddf28e-e76b-11f1-b5e7-e284dcf81adb'),(802,'storage.write:/31ddf28e-e76b-11f1-b5e7-e284dcf81adb'),(803,'storage.modify:/31ddf4e3-e76b-11f1-b5e7-e284dcf81adb'),(803,'storage.read:/31ddf4e3-e76b-11f1-b5e7-e284dcf81adb'),(803,'storage.write:/31ddf4e3-e76b-11f1-b5e7-e284dcf81adb'),(804,'storage.modify:/31df2c74-e76b-11f1-b5e7-e284dcf81adb'),(804,'storage.read:/31df2c74-e76b-11f1-b5e7-e284dcf81adb'),(804,'storage.write:/31df2c74-e76b-11f1-b5e7-e284dcf81adb'),(805,'storage.modify:/31df318d-e76b-11f1-b5e7-e284dcf81adb'),(805,'storage.read:/31df318d-e76b-11f1-b5e7-e284dcf81adb'),(805,'storage.write:/31df318d-e76b-11f1-b5e7-e284dcf81adb'),(806,'storage.modify:/31df34b0-e76b-11f1-b5e7-e284dcf81adb'),(806,'storage.read:/31df34b0-e76b-11f1-b5e7-e284dcf81adb'),(806,'storage.write:/31df34b0-e76b-11f1-b5e7-e284dcf81adb'),(807,'storage.modify:/31df378b-e76b-11f1-b5e7-e284dcf81adb'),(807,'storage.read:/31df378b-e76b-11f1-b5e7-e284dcf81adb'),(807,'storage.write:/31df378b-e76b-11f1-b5e7-e284dcf81adb'),(808,'storage.modify:/31df3a52-e76b-11f1-b5e7-e284dcf81adb'),(808,'storage.read:/31df3a52-e76b-11f1-b5e7-e284dcf81adb'),(808,'storage.write:/31df3a52-e76b-11f1-b5e7-e284dcf81adb'),(809,'storage.modify:/31df3d56-e76b-11f1-b5e7-e284dcf81adb'),(809,'storage.read:/31df3d56-e76b-11f1-b5e7-e284dcf81adb'),(809,'storage.write:/31df3d56-e76b-11f1-b5e7-e284dcf81adb'),(810,'storage.modify:/31df3ffb-e76b-11f1-b5e7-e284dcf81adb'),(810,'storage.read:/31df3ffb-e76b-11f1-b5e7-e284dcf81adb'),(810,'storage.write:/31df3ffb-e76b-11f1-b5e7-e284dcf81adb'),(811,'storage.modify:/31df42b8-e76b-11f1-b5e7-e284dcf81adb'),(811,'storage.read:/31df42b8-e76b-11f1-b5e7-e284dcf81adb'),(811,'storage.write:/31df42b8-e76b-11f1-b5e7-e284dcf81adb'),(812,'storage.modify:/31df451d-e76b-11f1-b5e7-e284dcf81adb'),(812,'storage.read:/31df451d-e76b-11f1-b5e7-e284dcf81adb'),(812,'storage.write:/31df451d-e76b-11f1-b5e7-e284dcf81adb'),(813,'storage.modify:/31df476f-e76b-11f1-b5e7-e284dcf81adb'),(813,'storage.read:/31df476f-e76b-11f1-b5e7-e284dcf81adb'),(813,'storage.write:/31df476f-e76b-11f1-b5e7-e284dcf81adb'),(814,'storage.modify:/31df49ba-e76b-11f1-b5e7-e284dcf81adb'),(814,'storage.read:/31df49ba-e76b-11f1-b5e7-e284dcf81adb'),(814,'storage.write:/31df49ba-e76b-11f1-b5e7-e284dcf81adb'),(815,'storage.modify:/31df4c08-e76b-11f1-b5e7-e284dcf81adb'),(815,'storage.read:/31df4c08-e76b-11f1-b5e7-e284dcf81adb'),(815,'storage.write:/31df4c08-e76b-11f1-b5e7-e284dcf81adb'),(816,'storage.modify:/31df4e5a-e76b-11f1-b5e7-e284dcf81adb'),(816,'storage.read:/31df4e5a-e76b-11f1-b5e7-e284dcf81adb'),(816,'storage.write:/31df4e5a-e76b-11f1-b5e7-e284dcf81adb'),(817,'storage.modify:/31df51fe-e76b-11f1-b5e7-e284dcf81adb'),(817,'storage.read:/31df51fe-e76b-11f1-b5e7-e284dcf81adb'),(817,'storage.write:/31df51fe-e76b-11f1-b5e7-e284dcf81adb'),(818,'storage.modify:/31e0ab4b-e76b-11f1-b5e7-e284dcf81adb'),(818,'storage.read:/31e0ab4b-e76b-11f1-b5e7-e284dcf81adb'),(818,'storage.write:/31e0ab4b-e76b-11f1-b5e7-e284dcf81adb'),(819,'storage.modify:/31e0af4e-e76b-11f1-b5e7-e284dcf81adb'),(819,'storage.read:/31e0af4e-e76b-11f1-b5e7-e284dcf81adb'),(819,'storage.write:/31e0af4e-e76b-11f1-b5e7-e284dcf81adb'),(820,'storage.modify:/31e0b1e2-e76b-11f1-b5e7-e284dcf81adb'),(820,'storage.read:/31e0b1e2-e76b-11f1-b5e7-e284dcf81adb'),(820,'storage.write:/31e0b1e2-e76b-11f1-b5e7-e284dcf81adb'),(821,'storage.modify:/31e0b4b6-e76b-11f1-b5e7-e284dcf81adb'),(821,'storage.read:/31e0b4b6-e76b-11f1-b5e7-e284dcf81adb'),(821,'storage.write:/31e0b4b6-e76b-11f1-b5e7-e284dcf81adb'),(822,'storage.modify:/31e0b722-e76b-11f1-b5e7-e284dcf81adb'),(822,'storage.read:/31e0b722-e76b-11f1-b5e7-e284dcf81adb'),(822,'storage.write:/31e0b722-e76b-11f1-b5e7-e284dcf81adb'),(823,'storage.modify:/31e0b97a-e76b-11f1-b5e7-e284dcf81adb'),(823,'storage.read:/31e0b97a-e76b-11f1-b5e7-e284dcf81adb'),(823,'storage.write:/31e0b97a-e76b-11f1-b5e7-e284dcf81adb'),(824,'storage.modify:/31e0bbca-e76b-11f1-b5e7-e284dcf81adb'),(824,'storage.read:/31e0bbca-e76b-11f1-b5e7-e284dcf81adb'),(824,'storage.write:/31e0bbca-e76b-11f1-b5e7-e284dcf81adb'),(825,'storage.modify:/31e0be25-e76b-11f1-b5e7-e284dcf81adb'),(825,'storage.read:/31e0be25-e76b-11f1-b5e7-e284dcf81adb'),(825,'storage.write:/31e0be25-e76b-11f1-b5e7-e284dcf81adb'),(826,'storage.modify:/31e0c070-e76b-11f1-b5e7-e284dcf81adb'),(826,'storage.read:/31e0c070-e76b-11f1-b5e7-e284dcf81adb'),(826,'storage.write:/31e0c070-e76b-11f1-b5e7-e284dcf81adb'),(827,'storage.modify:/31e3c10d-e76b-11f1-b5e7-e284dcf81adb'),(827,'storage.read:/31e3c10d-e76b-11f1-b5e7-e284dcf81adb'),(827,'storage.write:/31e3c10d-e76b-11f1-b5e7-e284dcf81adb'),(828,'storage.modify:/31e3c7d3-e76b-11f1-b5e7-e284dcf81adb'),(828,'storage.read:/31e3c7d3-e76b-11f1-b5e7-e284dcf81adb'),(828,'storage.write:/31e3c7d3-e76b-11f1-b5e7-e284dcf81adb'),(829,'storage.modify:/31e3cb70-e76b-11f1-b5e7-e284dcf81adb'),(829,'storage.read:/31e3cb70-e76b-11f1-b5e7-e284dcf81adb'),(829,'storage.write:/31e3cb70-e76b-11f1-b5e7-e284dcf81adb'),(830,'storage.modify:/31e4942c-e76b-11f1-b5e7-e284dcf81adb'),(830,'storage.read:/31e4942c-e76b-11f1-b5e7-e284dcf81adb'),(830,'storage.write:/31e4942c-e76b-11f1-b5e7-e284dcf81adb'),(831,'storage.modify:/31e49781-e76b-11f1-b5e7-e284dcf81adb'),(831,'storage.read:/31e49781-e76b-11f1-b5e7-e284dcf81adb'),(831,'storage.write:/31e49781-e76b-11f1-b5e7-e284dcf81adb'),(832,'storage.modify:/31e49a3e-e76b-11f1-b5e7-e284dcf81adb'),(832,'storage.read:/31e49a3e-e76b-11f1-b5e7-e284dcf81adb'),(832,'storage.write:/31e49a3e-e76b-11f1-b5e7-e284dcf81adb'),(833,'storage.modify:/31e49cb3-e76b-11f1-b5e7-e284dcf81adb'),(833,'storage.read:/31e49cb3-e76b-11f1-b5e7-e284dcf81adb'),(833,'storage.write:/31e49cb3-e76b-11f1-b5e7-e284dcf81adb'),(834,'storage.modify:/31e49f10-e76b-11f1-b5e7-e284dcf81adb'),(834,'storage.read:/31e49f10-e76b-11f1-b5e7-e284dcf81adb'),(834,'storage.write:/31e49f10-e76b-11f1-b5e7-e284dcf81adb'),(835,'storage.modify:/31e4a169-e76b-11f1-b5e7-e284dcf81adb'),(835,'storage.read:/31e4a169-e76b-11f1-b5e7-e284dcf81adb'),(835,'storage.write:/31e4a169-e76b-11f1-b5e7-e284dcf81adb'),(836,'storage.modify:/31e4a3bd-e76b-11f1-b5e7-e284dcf81adb'),(836,'storage.read:/31e4a3bd-e76b-11f1-b5e7-e284dcf81adb'),(836,'storage.write:/31e4a3bd-e76b-11f1-b5e7-e284dcf81adb'),(837,'storage.modify:/31e4a616-e76b-11f1-b5e7-e284dcf81adb'),(837,'storage.read:/31e4a616-e76b-11f1-b5e7-e284dcf81adb'),(837,'storage.write:/31e4a616-e76b-11f1-b5e7-e284dcf81adb'),(838,'storage.modify:/31e4a863-e76b-11f1-b5e7-e284dcf81adb'),(838,'storage.read:/31e4a863-e76b-11f1-b5e7-e284dcf81adb'),(838,'storage.write:/31e4a863-e76b-11f1-b5e7-e284dcf81adb'),(839,'storage.modify:/31e4aab7-e76b-11f1-b5e7-e284dcf81adb'),(839,'storage.read:/31e4aab7-e76b-11f1-b5e7-e284dcf81adb'),(839,'storage.write:/31e4aab7-e76b-11f1-b5e7-e284dcf81adb'),(840,'storage.modify:/31e4ad06-e76b-11f1-b5e7-e284dcf81adb'),(840,'storage.read:/31e4ad06-e76b-11f1-b5e7-e284dcf81adb'),(840,'storage.write:/31e4ad06-e76b-11f1-b5e7-e284dcf81adb'),(841,'storage.modify:/31e4af5c-e76b-11f1-b5e7-e284dcf81adb'),(841,'storage.read:/31e4af5c-e76b-11f1-b5e7-e284dcf81adb'),(841,'storage.write:/31e4af5c-e76b-11f1-b5e7-e284dcf81adb'),(842,'storage.modify:/31e4b1aa-e76b-11f1-b5e7-e284dcf81adb'),(842,'storage.read:/31e4b1aa-e76b-11f1-b5e7-e284dcf81adb'),(842,'storage.write:/31e4b1aa-e76b-11f1-b5e7-e284dcf81adb'),(843,'storage.modify:/31e4b3f8-e76b-11f1-b5e7-e284dcf81adb'),(843,'storage.read:/31e4b3f8-e76b-11f1-b5e7-e284dcf81adb'),(843,'storage.write:/31e4b3f8-e76b-11f1-b5e7-e284dcf81adb'),(844,'storage.modify:/31e4b647-e76b-11f1-b5e7-e284dcf81adb'),(844,'storage.read:/31e4b647-e76b-11f1-b5e7-e284dcf81adb'),(844,'storage.write:/31e4b647-e76b-11f1-b5e7-e284dcf81adb'),(845,'storage.modify:/31e4b898-e76b-11f1-b5e7-e284dcf81adb'),(845,'storage.read:/31e4b898-e76b-11f1-b5e7-e284dcf81adb'),(845,'storage.write:/31e4b898-e76b-11f1-b5e7-e284dcf81adb'),(846,'storage.modify:/31e4bc05-e76b-11f1-b5e7-e284dcf81adb'),(846,'storage.read:/31e4bc05-e76b-11f1-b5e7-e284dcf81adb'),(846,'storage.write:/31e4bc05-e76b-11f1-b5e7-e284dcf81adb'),(847,'storage.modify:/31e4be60-e76b-11f1-b5e7-e284dcf81adb'),(847,'storage.read:/31e4be60-e76b-11f1-b5e7-e284dcf81adb'),(847,'storage.write:/31e4be60-e76b-11f1-b5e7-e284dcf81adb'),(848,'storage.modify:/31e4c0f1-e76b-11f1-b5e7-e284dcf81adb'),(848,'storage.read:/31e4c0f1-e76b-11f1-b5e7-e284dcf81adb'),(848,'storage.write:/31e4c0f1-e76b-11f1-b5e7-e284dcf81adb'),(849,'storage.modify:/31e4c34e-e76b-11f1-b5e7-e284dcf81adb'),(849,'storage.read:/31e4c34e-e76b-11f1-b5e7-e284dcf81adb'),(849,'storage.write:/31e4c34e-e76b-11f1-b5e7-e284dcf81adb'),(850,'storage.modify:/31e4c5a0-e76b-11f1-b5e7-e284dcf81adb'),(850,'storage.read:/31e4c5a0-e76b-11f1-b5e7-e284dcf81adb'),(850,'storage.write:/31e4c5a0-e76b-11f1-b5e7-e284dcf81adb'),(851,'storage.modify:/31e4c7ee-e76b-11f1-b5e7-e284dcf81adb'),(851,'storage.read:/31e4c7ee-e76b-11f1-b5e7-e284dcf81adb'),(851,'storage.write:/31e4c7ee-e76b-11f1-b5e7-e284dcf81adb'),(852,'storage.modify:/31e4ca39-e76b-11f1-b5e7-e284dcf81adb'),(852,'storage.read:/31e4ca39-e76b-11f1-b5e7-e284dcf81adb'),(852,'storage.write:/31e4ca39-e76b-11f1-b5e7-e284dcf81adb'),(853,'storage.modify:/31e4cc84-e76b-11f1-b5e7-e284dcf81adb'),(853,'storage.read:/31e4cc84-e76b-11f1-b5e7-e284dcf81adb'),(853,'storage.write:/31e4cc84-e76b-11f1-b5e7-e284dcf81adb'),(854,'storage.modify:/31e4cecc-e76b-11f1-b5e7-e284dcf81adb'),(854,'storage.read:/31e4cecc-e76b-11f1-b5e7-e284dcf81adb'),(854,'storage.write:/31e4cecc-e76b-11f1-b5e7-e284dcf81adb'),(855,'storage.modify:/31e4d113-e76b-11f1-b5e7-e284dcf81adb'),(855,'storage.read:/31e4d113-e76b-11f1-b5e7-e284dcf81adb'),(855,'storage.write:/31e4d113-e76b-11f1-b5e7-e284dcf81adb'),(856,'storage.modify:/31e4d35b-e76b-11f1-b5e7-e284dcf81adb'),(856,'storage.read:/31e4d35b-e76b-11f1-b5e7-e284dcf81adb'),(856,'storage.write:/31e4d35b-e76b-11f1-b5e7-e284dcf81adb'),(857,'storage.modify:/31e4d5a8-e76b-11f1-b5e7-e284dcf81adb'),(857,'storage.read:/31e4d5a8-e76b-11f1-b5e7-e284dcf81adb'),(857,'storage.write:/31e4d5a8-e76b-11f1-b5e7-e284dcf81adb'),(858,'storage.modify:/31e4d7f5-e76b-11f1-b5e7-e284dcf81adb'),(858,'storage.read:/31e4d7f5-e76b-11f1-b5e7-e284dcf81adb'),(858,'storage.write:/31e4d7f5-e76b-11f1-b5e7-e284dcf81adb'),(859,'storage.modify:/31e4da9b-e76b-11f1-b5e7-e284dcf81adb'),(859,'storage.read:/31e4da9b-e76b-11f1-b5e7-e284dcf81adb'),(859,'storage.write:/31e4da9b-e76b-11f1-b5e7-e284dcf81adb'),(860,'storage.modify:/31e4dcf3-e76b-11f1-b5e7-e284dcf81adb'),(860,'storage.read:/31e4dcf3-e76b-11f1-b5e7-e284dcf81adb'),(860,'storage.write:/31e4dcf3-e76b-11f1-b5e7-e284dcf81adb'),(861,'storage.modify:/31e4df3f-e76b-11f1-b5e7-e284dcf81adb'),(861,'storage.read:/31e4df3f-e76b-11f1-b5e7-e284dcf81adb'),(861,'storage.write:/31e4df3f-e76b-11f1-b5e7-e284dcf81adb'),(862,'storage.modify:/31e4e188-e76b-11f1-b5e7-e284dcf81adb'),(862,'storage.read:/31e4e188-e76b-11f1-b5e7-e284dcf81adb'),(862,'storage.write:/31e4e188-e76b-11f1-b5e7-e284dcf81adb'),(863,'storage.modify:/31e68e92-e76b-11f1-b5e7-e284dcf81adb'),(863,'storage.read:/31e68e92-e76b-11f1-b5e7-e284dcf81adb'),(863,'storage.write:/31e68e92-e76b-11f1-b5e7-e284dcf81adb'),(864,'storage.modify:/31e69474-e76b-11f1-b5e7-e284dcf81adb'),(864,'storage.read:/31e69474-e76b-11f1-b5e7-e284dcf81adb'),(864,'storage.write:/31e69474-e76b-11f1-b5e7-e284dcf81adb'),(865,'storage.modify:/31e697f4-e76b-11f1-b5e7-e284dcf81adb'),(865,'storage.read:/31e697f4-e76b-11f1-b5e7-e284dcf81adb'),(865,'storage.write:/31e697f4-e76b-11f1-b5e7-e284dcf81adb'),(866,'storage.modify:/31e69a8f-e76b-11f1-b5e7-e284dcf81adb'),(866,'storage.read:/31e69a8f-e76b-11f1-b5e7-e284dcf81adb'),(866,'storage.write:/31e69a8f-e76b-11f1-b5e7-e284dcf81adb'),(867,'storage.modify:/31e69d1f-e76b-11f1-b5e7-e284dcf81adb'),(867,'storage.read:/31e69d1f-e76b-11f1-b5e7-e284dcf81adb'),(867,'storage.write:/31e69d1f-e76b-11f1-b5e7-e284dcf81adb'),(868,'storage.modify:/31e69fa3-e76b-11f1-b5e7-e284dcf81adb'),(868,'storage.read:/31e69fa3-e76b-11f1-b5e7-e284dcf81adb'),(868,'storage.write:/31e69fa3-e76b-11f1-b5e7-e284dcf81adb'),(869,'storage.modify:/31e6a21d-e76b-11f1-b5e7-e284dcf81adb'),(869,'storage.read:/31e6a21d-e76b-11f1-b5e7-e284dcf81adb'),(869,'storage.write:/31e6a21d-e76b-11f1-b5e7-e284dcf81adb'),(870,'storage.modify:/31e6a49b-e76b-11f1-b5e7-e284dcf81adb'),(870,'storage.read:/31e6a49b-e76b-11f1-b5e7-e284dcf81adb'),(870,'storage.write:/31e6a49b-e76b-11f1-b5e7-e284dcf81adb'),(871,'storage.modify:/31e6a70b-e76b-11f1-b5e7-e284dcf81adb'),(871,'storage.read:/31e6a70b-e76b-11f1-b5e7-e284dcf81adb'),(871,'storage.write:/31e6a70b-e76b-11f1-b5e7-e284dcf81adb'),(872,'storage.modify:/31e6a976-e76b-11f1-b5e7-e284dcf81adb'),(872,'storage.read:/31e6a976-e76b-11f1-b5e7-e284dcf81adb'),(872,'storage.write:/31e6a976-e76b-11f1-b5e7-e284dcf81adb'),(873,'storage.modify:/31e6abe3-e76b-11f1-b5e7-e284dcf81adb'),(873,'storage.read:/31e6abe3-e76b-11f1-b5e7-e284dcf81adb'),(873,'storage.write:/31e6abe3-e76b-11f1-b5e7-e284dcf81adb'),(874,'storage.modify:/31e6ae5d-e76b-11f1-b5e7-e284dcf81adb'),(874,'storage.read:/31e6ae5d-e76b-11f1-b5e7-e284dcf81adb'),(874,'storage.write:/31e6ae5d-e76b-11f1-b5e7-e284dcf81adb'),(875,'storage.modify:/31e6b0b4-e76b-11f1-b5e7-e284dcf81adb'),(875,'storage.read:/31e6b0b4-e76b-11f1-b5e7-e284dcf81adb'),(875,'storage.write:/31e6b0b4-e76b-11f1-b5e7-e284dcf81adb'),(876,'storage.modify:/31e6b309-e76b-11f1-b5e7-e284dcf81adb'),(876,'storage.read:/31e6b309-e76b-11f1-b5e7-e284dcf81adb'),(876,'storage.write:/31e6b309-e76b-11f1-b5e7-e284dcf81adb'),(877,'storage.modify:/31e6b5cf-e76b-11f1-b5e7-e284dcf81adb'),(877,'storage.read:/31e6b5cf-e76b-11f1-b5e7-e284dcf81adb'),(877,'storage.write:/31e6b5cf-e76b-11f1-b5e7-e284dcf81adb'),(878,'storage.modify:/31e6b833-e76b-11f1-b5e7-e284dcf81adb'),(878,'storage.read:/31e6b833-e76b-11f1-b5e7-e284dcf81adb'),(878,'storage.write:/31e6b833-e76b-11f1-b5e7-e284dcf81adb'),(879,'storage.modify:/31e6ba88-e76b-11f1-b5e7-e284dcf81adb'),(879,'storage.read:/31e6ba88-e76b-11f1-b5e7-e284dcf81adb'),(879,'storage.write:/31e6ba88-e76b-11f1-b5e7-e284dcf81adb'),(880,'storage.modify:/31e6bd35-e76b-11f1-b5e7-e284dcf81adb'),(880,'storage.read:/31e6bd35-e76b-11f1-b5e7-e284dcf81adb'),(880,'storage.write:/31e6bd35-e76b-11f1-b5e7-e284dcf81adb'),(881,'storage.modify:/31e6bf98-e76b-11f1-b5e7-e284dcf81adb'),(881,'storage.read:/31e6bf98-e76b-11f1-b5e7-e284dcf81adb'),(881,'storage.write:/31e6bf98-e76b-11f1-b5e7-e284dcf81adb'),(882,'storage.modify:/31e6c1ee-e76b-11f1-b5e7-e284dcf81adb'),(882,'storage.read:/31e6c1ee-e76b-11f1-b5e7-e284dcf81adb'),(882,'storage.write:/31e6c1ee-e76b-11f1-b5e7-e284dcf81adb'),(883,'storage.modify:/31e6c43e-e76b-11f1-b5e7-e284dcf81adb'),(883,'storage.read:/31e6c43e-e76b-11f1-b5e7-e284dcf81adb'),(883,'storage.write:/31e6c43e-e76b-11f1-b5e7-e284dcf81adb'),(884,'storage.modify:/31e6c780-e76b-11f1-b5e7-e284dcf81adb'),(884,'storage.read:/31e6c780-e76b-11f1-b5e7-e284dcf81adb'),(884,'storage.write:/31e6c780-e76b-11f1-b5e7-e284dcf81adb'),(885,'storage.modify:/31e6c9f3-e76b-11f1-b5e7-e284dcf81adb'),(885,'storage.read:/31e6c9f3-e76b-11f1-b5e7-e284dcf81adb'),(885,'storage.write:/31e6c9f3-e76b-11f1-b5e7-e284dcf81adb'),(886,'storage.modify:/31e6cc4a-e76b-11f1-b5e7-e284dcf81adb'),(886,'storage.read:/31e6cc4a-e76b-11f1-b5e7-e284dcf81adb'),(886,'storage.write:/31e6cc4a-e76b-11f1-b5e7-e284dcf81adb'),(887,'storage.modify:/31e6ce9e-e76b-11f1-b5e7-e284dcf81adb'),(887,'storage.read:/31e6ce9e-e76b-11f1-b5e7-e284dcf81adb'),(887,'storage.write:/31e6ce9e-e76b-11f1-b5e7-e284dcf81adb'),(888,'storage.modify:/31e6d202-e76b-11f1-b5e7-e284dcf81adb'),(888,'storage.read:/31e6d202-e76b-11f1-b5e7-e284dcf81adb'),(888,'storage.write:/31e6d202-e76b-11f1-b5e7-e284dcf81adb'),(889,'storage.modify:/31e6d4bf-e76b-11f1-b5e7-e284dcf81adb'),(889,'storage.read:/31e6d4bf-e76b-11f1-b5e7-e284dcf81adb'),(889,'storage.write:/31e6d4bf-e76b-11f1-b5e7-e284dcf81adb'),(890,'storage.modify:/31e6d717-e76b-11f1-b5e7-e284dcf81adb'),(890,'storage.read:/31e6d717-e76b-11f1-b5e7-e284dcf81adb'),(890,'storage.write:/31e6d717-e76b-11f1-b5e7-e284dcf81adb'),(891,'storage.modify:/31e6d967-e76b-11f1-b5e7-e284dcf81adb'),(891,'storage.read:/31e6d967-e76b-11f1-b5e7-e284dcf81adb'),(891,'storage.write:/31e6d967-e76b-11f1-b5e7-e284dcf81adb'),(892,'storage.modify:/31e6dc1c-e76b-11f1-b5e7-e284dcf81adb'),(892,'storage.read:/31e6dc1c-e76b-11f1-b5e7-e284dcf81adb'),(892,'storage.write:/31e6dc1c-e76b-11f1-b5e7-e284dcf81adb'),(893,'storage.modify:/31e6de6c-e76b-11f1-b5e7-e284dcf81adb'),(893,'storage.read:/31e6de6c-e76b-11f1-b5e7-e284dcf81adb'),(893,'storage.write:/31e6de6c-e76b-11f1-b5e7-e284dcf81adb'),(894,'storage.modify:/31e6e0b5-e76b-11f1-b5e7-e284dcf81adb'),(894,'storage.read:/31e6e0b5-e76b-11f1-b5e7-e284dcf81adb'),(894,'storage.write:/31e6e0b5-e76b-11f1-b5e7-e284dcf81adb'),(895,'storage.modify:/31e6e301-e76b-11f1-b5e7-e284dcf81adb'),(895,'storage.read:/31e6e301-e76b-11f1-b5e7-e284dcf81adb'),(895,'storage.write:/31e6e301-e76b-11f1-b5e7-e284dcf81adb'),(896,'storage.modify:/31e6e5c4-e76b-11f1-b5e7-e284dcf81adb'),(896,'storage.read:/31e6e5c4-e76b-11f1-b5e7-e284dcf81adb'),(896,'storage.write:/31e6e5c4-e76b-11f1-b5e7-e284dcf81adb'),(897,'storage.modify:/31e6e818-e76b-11f1-b5e7-e284dcf81adb'),(897,'storage.read:/31e6e818-e76b-11f1-b5e7-e284dcf81adb'),(897,'storage.write:/31e6e818-e76b-11f1-b5e7-e284dcf81adb'),(898,'storage.modify:/31e6ea60-e76b-11f1-b5e7-e284dcf81adb'),(898,'storage.read:/31e6ea60-e76b-11f1-b5e7-e284dcf81adb'),(898,'storage.write:/31e6ea60-e76b-11f1-b5e7-e284dcf81adb'),(899,'storage.modify:/31e6eca8-e76b-11f1-b5e7-e284dcf81adb'),(899,'storage.read:/31e6eca8-e76b-11f1-b5e7-e284dcf81adb'),(899,'storage.write:/31e6eca8-e76b-11f1-b5e7-e284dcf81adb'),(900,'storage.modify:/31e6ef12-e76b-11f1-b5e7-e284dcf81adb'),(900,'storage.read:/31e6ef12-e76b-11f1-b5e7-e284dcf81adb'),(900,'storage.write:/31e6ef12-e76b-11f1-b5e7-e284dcf81adb'),(901,'storage.modify:/31e6f200-e76b-11f1-b5e7-e284dcf81adb'),(901,'storage.read:/31e6f200-e76b-11f1-b5e7-e284dcf81adb'),(901,'storage.write:/31e6f200-e76b-11f1-b5e7-e284dcf81adb'),(902,'storage.modify:/31f230ac-e76b-11f1-b5e7-e284dcf81adb'),(902,'storage.read:/31f230ac-e76b-11f1-b5e7-e284dcf81adb'),(902,'storage.write:/31f230ac-e76b-11f1-b5e7-e284dcf81adb'),(903,'storage.modify:/31f237ac-e76b-11f1-b5e7-e284dcf81adb'),(903,'storage.read:/31f237ac-e76b-11f1-b5e7-e284dcf81adb'),(903,'storage.write:/31f237ac-e76b-11f1-b5e7-e284dcf81adb'),(904,'storage.modify:/31f23a7a-e76b-11f1-b5e7-e284dcf81adb'),(904,'storage.read:/31f23a7a-e76b-11f1-b5e7-e284dcf81adb'),(904,'storage.write:/31f23a7a-e76b-11f1-b5e7-e284dcf81adb'),(905,'storage.modify:/31f23cf8-e76b-11f1-b5e7-e284dcf81adb'),(905,'storage.read:/31f23cf8-e76b-11f1-b5e7-e284dcf81adb'),(905,'storage.write:/31f23cf8-e76b-11f1-b5e7-e284dcf81adb'),(906,'storage.modify:/31f23f70-e76b-11f1-b5e7-e284dcf81adb'),(906,'storage.read:/31f23f70-e76b-11f1-b5e7-e284dcf81adb'),(906,'storage.write:/31f23f70-e76b-11f1-b5e7-e284dcf81adb'),(907,'storage.modify:/31f241d8-e76b-11f1-b5e7-e284dcf81adb'),(907,'storage.read:/31f241d8-e76b-11f1-b5e7-e284dcf81adb'),(907,'storage.write:/31f241d8-e76b-11f1-b5e7-e284dcf81adb'),(908,'storage.modify:/31f24455-e76b-11f1-b5e7-e284dcf81adb'),(908,'storage.read:/31f24455-e76b-11f1-b5e7-e284dcf81adb'),(908,'storage.write:/31f24455-e76b-11f1-b5e7-e284dcf81adb'),(909,'storage.modify:/31f2471d-e76b-11f1-b5e7-e284dcf81adb'),(909,'storage.read:/31f2471d-e76b-11f1-b5e7-e284dcf81adb'),(909,'storage.write:/31f2471d-e76b-11f1-b5e7-e284dcf81adb'),(910,'storage.modify:/31f24b44-e76b-11f1-b5e7-e284dcf81adb'),(910,'storage.read:/31f24b44-e76b-11f1-b5e7-e284dcf81adb'),(910,'storage.write:/31f24b44-e76b-11f1-b5e7-e284dcf81adb'),(911,'storage.modify:/31f24f7f-e76b-11f1-b5e7-e284dcf81adb'),(911,'storage.read:/31f24f7f-e76b-11f1-b5e7-e284dcf81adb'),(911,'storage.write:/31f24f7f-e76b-11f1-b5e7-e284dcf81adb'),(912,'storage.modify:/31f253d8-e76b-11f1-b5e7-e284dcf81adb'),(912,'storage.read:/31f253d8-e76b-11f1-b5e7-e284dcf81adb'),(912,'storage.write:/31f253d8-e76b-11f1-b5e7-e284dcf81adb'),(913,'storage.modify:/31f25825-e76b-11f1-b5e7-e284dcf81adb'),(913,'storage.read:/31f25825-e76b-11f1-b5e7-e284dcf81adb'),(913,'storage.write:/31f25825-e76b-11f1-b5e7-e284dcf81adb'),(914,'storage.modify:/31f25b5d-e76b-11f1-b5e7-e284dcf81adb'),(914,'storage.read:/31f25b5d-e76b-11f1-b5e7-e284dcf81adb'),(914,'storage.write:/31f25b5d-e76b-11f1-b5e7-e284dcf81adb'),(915,'storage.modify:/31f25dca-e76b-11f1-b5e7-e284dcf81adb'),(915,'storage.read:/31f25dca-e76b-11f1-b5e7-e284dcf81adb'),(915,'storage.write:/31f25dca-e76b-11f1-b5e7-e284dcf81adb'),(916,'storage.modify:/31f2616f-e76b-11f1-b5e7-e284dcf81adb'),(916,'storage.read:/31f2616f-e76b-11f1-b5e7-e284dcf81adb'),(916,'storage.write:/31f2616f-e76b-11f1-b5e7-e284dcf81adb'),(917,'storage.modify:/31f265da-e76b-11f1-b5e7-e284dcf81adb'),(917,'storage.read:/31f265da-e76b-11f1-b5e7-e284dcf81adb'),(917,'storage.write:/31f265da-e76b-11f1-b5e7-e284dcf81adb'),(918,'storage.modify:/31f26903-e76b-11f1-b5e7-e284dcf81adb'),(918,'storage.read:/31f26903-e76b-11f1-b5e7-e284dcf81adb'),(918,'storage.write:/31f26903-e76b-11f1-b5e7-e284dcf81adb'),(919,'storage.modify:/31f26b71-e76b-11f1-b5e7-e284dcf81adb'),(919,'storage.read:/31f26b71-e76b-11f1-b5e7-e284dcf81adb'),(919,'storage.write:/31f26b71-e76b-11f1-b5e7-e284dcf81adb'),(920,'storage.modify:/31f26f28-e76b-11f1-b5e7-e284dcf81adb'),(920,'storage.read:/31f26f28-e76b-11f1-b5e7-e284dcf81adb'),(920,'storage.write:/31f26f28-e76b-11f1-b5e7-e284dcf81adb'),(921,'storage.modify:/31f27364-e76b-11f1-b5e7-e284dcf81adb'),(921,'storage.read:/31f27364-e76b-11f1-b5e7-e284dcf81adb'),(921,'storage.write:/31f27364-e76b-11f1-b5e7-e284dcf81adb'),(922,'storage.modify:/31f41d4d-e76b-11f1-b5e7-e284dcf81adb'),(922,'storage.read:/31f41d4d-e76b-11f1-b5e7-e284dcf81adb'),(922,'storage.write:/31f41d4d-e76b-11f1-b5e7-e284dcf81adb'),(923,'storage.modify:/31f423e2-e76b-11f1-b5e7-e284dcf81adb'),(923,'storage.read:/31f423e2-e76b-11f1-b5e7-e284dcf81adb'),(923,'storage.write:/31f423e2-e76b-11f1-b5e7-e284dcf81adb'),(924,'storage.modify:/31f426d6-e76b-11f1-b5e7-e284dcf81adb'),(924,'storage.read:/31f426d6-e76b-11f1-b5e7-e284dcf81adb'),(924,'storage.write:/31f426d6-e76b-11f1-b5e7-e284dcf81adb'),(925,'storage.modify:/31f42950-e76b-11f1-b5e7-e284dcf81adb'),(925,'storage.read:/31f42950-e76b-11f1-b5e7-e284dcf81adb'),(925,'storage.write:/31f42950-e76b-11f1-b5e7-e284dcf81adb'),(926,'storage.modify:/31f42c07-e76b-11f1-b5e7-e284dcf81adb'),(926,'storage.read:/31f42c07-e76b-11f1-b5e7-e284dcf81adb'),(926,'storage.write:/31f42c07-e76b-11f1-b5e7-e284dcf81adb'),(927,'storage.modify:/31f42e5e-e76b-11f1-b5e7-e284dcf81adb'),(927,'storage.read:/31f42e5e-e76b-11f1-b5e7-e284dcf81adb'),(927,'storage.write:/31f42e5e-e76b-11f1-b5e7-e284dcf81adb'),(928,'storage.modify:/31f430b2-e76b-11f1-b5e7-e284dcf81adb'),(928,'storage.read:/31f430b2-e76b-11f1-b5e7-e284dcf81adb'),(928,'storage.write:/31f430b2-e76b-11f1-b5e7-e284dcf81adb'),(929,'storage.modify:/31f4330e-e76b-11f1-b5e7-e284dcf81adb'),(929,'storage.read:/31f4330e-e76b-11f1-b5e7-e284dcf81adb'),(929,'storage.write:/31f4330e-e76b-11f1-b5e7-e284dcf81adb'),(930,'storage.modify:/31f4355e-e76b-11f1-b5e7-e284dcf81adb'),(930,'storage.read:/31f4355e-e76b-11f1-b5e7-e284dcf81adb'),(930,'storage.write:/31f4355e-e76b-11f1-b5e7-e284dcf81adb'),(931,'storage.modify:/31f437aa-e76b-11f1-b5e7-e284dcf81adb'),(931,'storage.read:/31f437aa-e76b-11f1-b5e7-e284dcf81adb'),(931,'storage.write:/31f437aa-e76b-11f1-b5e7-e284dcf81adb'),(932,'storage.modify:/31f439f2-e76b-11f1-b5e7-e284dcf81adb'),(932,'storage.read:/31f439f2-e76b-11f1-b5e7-e284dcf81adb'),(932,'storage.write:/31f439f2-e76b-11f1-b5e7-e284dcf81adb'),(933,'storage.modify:/31f43c3b-e76b-11f1-b5e7-e284dcf81adb'),(933,'storage.read:/31f43c3b-e76b-11f1-b5e7-e284dcf81adb'),(933,'storage.write:/31f43c3b-e76b-11f1-b5e7-e284dcf81adb'),(934,'storage.modify:/31f43e86-e76b-11f1-b5e7-e284dcf81adb'),(934,'storage.read:/31f43e86-e76b-11f1-b5e7-e284dcf81adb'),(934,'storage.write:/31f43e86-e76b-11f1-b5e7-e284dcf81adb'),(935,'storage.modify:/31f440d0-e76b-11f1-b5e7-e284dcf81adb'),(935,'storage.read:/31f440d0-e76b-11f1-b5e7-e284dcf81adb'),(935,'storage.write:/31f440d0-e76b-11f1-b5e7-e284dcf81adb'),(936,'storage.modify:/31f44316-e76b-11f1-b5e7-e284dcf81adb'),(936,'storage.read:/31f44316-e76b-11f1-b5e7-e284dcf81adb'),(936,'storage.write:/31f44316-e76b-11f1-b5e7-e284dcf81adb'),(937,'storage.modify:/31f4455e-e76b-11f1-b5e7-e284dcf81adb'),(937,'storage.read:/31f4455e-e76b-11f1-b5e7-e284dcf81adb'),(937,'storage.write:/31f4455e-e76b-11f1-b5e7-e284dcf81adb'),(938,'storage.modify:/31f447a8-e76b-11f1-b5e7-e284dcf81adb'),(938,'storage.read:/31f447a8-e76b-11f1-b5e7-e284dcf81adb'),(938,'storage.write:/31f447a8-e76b-11f1-b5e7-e284dcf81adb'),(939,'storage.modify:/31f449f0-e76b-11f1-b5e7-e284dcf81adb'),(939,'storage.read:/31f449f0-e76b-11f1-b5e7-e284dcf81adb'),(939,'storage.write:/31f449f0-e76b-11f1-b5e7-e284dcf81adb'),(940,'storage.modify:/31f44c36-e76b-11f1-b5e7-e284dcf81adb'),(940,'storage.read:/31f44c36-e76b-11f1-b5e7-e284dcf81adb'),(940,'storage.write:/31f44c36-e76b-11f1-b5e7-e284dcf81adb'),(941,'storage.modify:/31f44e83-e76b-11f1-b5e7-e284dcf81adb'),(941,'storage.read:/31f44e83-e76b-11f1-b5e7-e284dcf81adb'),(941,'storage.write:/31f44e83-e76b-11f1-b5e7-e284dcf81adb'),(942,'storage.modify:/31f450f5-e76b-11f1-b5e7-e284dcf81adb'),(942,'storage.read:/31f450f5-e76b-11f1-b5e7-e284dcf81adb'),(942,'storage.write:/31f450f5-e76b-11f1-b5e7-e284dcf81adb'),(943,'storage.modify:/31f45350-e76b-11f1-b5e7-e284dcf81adb'),(943,'storage.read:/31f45350-e76b-11f1-b5e7-e284dcf81adb'),(943,'storage.write:/31f45350-e76b-11f1-b5e7-e284dcf81adb'),(944,'storage.modify:/31f4559b-e76b-11f1-b5e7-e284dcf81adb'),(944,'storage.read:/31f4559b-e76b-11f1-b5e7-e284dcf81adb'),(944,'storage.write:/31f4559b-e76b-11f1-b5e7-e284dcf81adb'),(945,'storage.modify:/31f457e7-e76b-11f1-b5e7-e284dcf81adb'),(945,'storage.read:/31f457e7-e76b-11f1-b5e7-e284dcf81adb'),(945,'storage.write:/31f457e7-e76b-11f1-b5e7-e284dcf81adb'),(946,'storage.modify:/31f45a2d-e76b-11f1-b5e7-e284dcf81adb'),(946,'storage.read:/31f45a2d-e76b-11f1-b5e7-e284dcf81adb'),(946,'storage.write:/31f45a2d-e76b-11f1-b5e7-e284dcf81adb'),(947,'storage.modify:/31f45c7b-e76b-11f1-b5e7-e284dcf81adb'),(947,'storage.read:/31f45c7b-e76b-11f1-b5e7-e284dcf81adb'),(947,'storage.write:/31f45c7b-e76b-11f1-b5e7-e284dcf81adb'),(948,'storage.modify:/31f45ec3-e76b-11f1-b5e7-e284dcf81adb'),(948,'storage.read:/31f45ec3-e76b-11f1-b5e7-e284dcf81adb'),(948,'storage.write:/31f45ec3-e76b-11f1-b5e7-e284dcf81adb'),(949,'storage.modify:/31f4610d-e76b-11f1-b5e7-e284dcf81adb'),(949,'storage.read:/31f4610d-e76b-11f1-b5e7-e284dcf81adb'),(949,'storage.write:/31f4610d-e76b-11f1-b5e7-e284dcf81adb'),(950,'storage.modify:/31f46356-e76b-11f1-b5e7-e284dcf81adb'),(950,'storage.read:/31f46356-e76b-11f1-b5e7-e284dcf81adb'),(950,'storage.write:/31f46356-e76b-11f1-b5e7-e284dcf81adb'),(951,'storage.modify:/31f465a4-e76b-11f1-b5e7-e284dcf81adb'),(951,'storage.read:/31f465a4-e76b-11f1-b5e7-e284dcf81adb'),(951,'storage.write:/31f465a4-e76b-11f1-b5e7-e284dcf81adb'),(952,'storage.modify:/31f467ee-e76b-11f1-b5e7-e284dcf81adb'),(952,'storage.read:/31f467ee-e76b-11f1-b5e7-e284dcf81adb'),(952,'storage.write:/31f467ee-e76b-11f1-b5e7-e284dcf81adb'),(953,'storage.modify:/31f46a3d-e76b-11f1-b5e7-e284dcf81adb'),(953,'storage.read:/31f46a3d-e76b-11f1-b5e7-e284dcf81adb'),(953,'storage.write:/31f46a3d-e76b-11f1-b5e7-e284dcf81adb'),(954,'storage.modify:/31f46c82-e76b-11f1-b5e7-e284dcf81adb'),(954,'storage.read:/31f46c82-e76b-11f1-b5e7-e284dcf81adb'),(954,'storage.write:/31f46c82-e76b-11f1-b5e7-e284dcf81adb'),(955,'storage.modify:/31f46ed4-e76b-11f1-b5e7-e284dcf81adb'),(955,'storage.read:/31f46ed4-e76b-11f1-b5e7-e284dcf81adb'),(955,'storage.write:/31f46ed4-e76b-11f1-b5e7-e284dcf81adb'),(956,'storage.modify:/31f47178-e76b-11f1-b5e7-e284dcf81adb'),(956,'storage.read:/31f47178-e76b-11f1-b5e7-e284dcf81adb'),(956,'storage.write:/31f47178-e76b-11f1-b5e7-e284dcf81adb'),(957,'storage.modify:/31f473e0-e76b-11f1-b5e7-e284dcf81adb'),(957,'storage.read:/31f473e0-e76b-11f1-b5e7-e284dcf81adb'),(957,'storage.write:/31f473e0-e76b-11f1-b5e7-e284dcf81adb'),(958,'storage.modify:/31f47631-e76b-11f1-b5e7-e284dcf81adb'),(958,'storage.read:/31f47631-e76b-11f1-b5e7-e284dcf81adb'),(958,'storage.write:/31f47631-e76b-11f1-b5e7-e284dcf81adb'),(959,'storage.modify:/31f479e3-e76b-11f1-b5e7-e284dcf81adb'),(959,'storage.read:/31f479e3-e76b-11f1-b5e7-e284dcf81adb'),(959,'storage.write:/31f479e3-e76b-11f1-b5e7-e284dcf81adb'),(960,'storage.modify:/31f47c92-e76b-11f1-b5e7-e284dcf81adb'),(960,'storage.read:/31f47c92-e76b-11f1-b5e7-e284dcf81adb'),(960,'storage.write:/31f47c92-e76b-11f1-b5e7-e284dcf81adb'),(961,'storage.modify:/31f47ee7-e76b-11f1-b5e7-e284dcf81adb'),(961,'storage.read:/31f47ee7-e76b-11f1-b5e7-e284dcf81adb'),(961,'storage.write:/31f47ee7-e76b-11f1-b5e7-e284dcf81adb'),(962,'storage.modify:/31f48137-e76b-11f1-b5e7-e284dcf81adb'),(962,'storage.read:/31f48137-e76b-11f1-b5e7-e284dcf81adb'),(962,'storage.write:/31f48137-e76b-11f1-b5e7-e284dcf81adb'),(963,'storage.modify:/31f48385-e76b-11f1-b5e7-e284dcf81adb'),(963,'storage.read:/31f48385-e76b-11f1-b5e7-e284dcf81adb'),(963,'storage.write:/31f48385-e76b-11f1-b5e7-e284dcf81adb'),(964,'storage.modify:/31f485d1-e76b-11f1-b5e7-e284dcf81adb'),(964,'storage.read:/31f485d1-e76b-11f1-b5e7-e284dcf81adb'),(964,'storage.write:/31f485d1-e76b-11f1-b5e7-e284dcf81adb'),(965,'storage.modify:/31f48827-e76b-11f1-b5e7-e284dcf81adb'),(965,'storage.read:/31f48827-e76b-11f1-b5e7-e284dcf81adb'),(965,'storage.write:/31f48827-e76b-11f1-b5e7-e284dcf81adb'),(966,'storage.modify:/31f48a6e-e76b-11f1-b5e7-e284dcf81adb'),(966,'storage.read:/31f48a6e-e76b-11f1-b5e7-e284dcf81adb'),(966,'storage.write:/31f48a6e-e76b-11f1-b5e7-e284dcf81adb'),(967,'storage.modify:/31f48cbf-e76b-11f1-b5e7-e284dcf81adb'),(967,'storage.read:/31f48cbf-e76b-11f1-b5e7-e284dcf81adb'),(967,'storage.write:/31f48cbf-e76b-11f1-b5e7-e284dcf81adb'),(968,'storage.modify:/31f48f05-e76b-11f1-b5e7-e284dcf81adb'),(968,'storage.read:/31f48f05-e76b-11f1-b5e7-e284dcf81adb'),(968,'storage.write:/31f48f05-e76b-11f1-b5e7-e284dcf81adb'),(969,'storage.modify:/31f49152-e76b-11f1-b5e7-e284dcf81adb'),(969,'storage.read:/31f49152-e76b-11f1-b5e7-e284dcf81adb'),(969,'storage.write:/31f49152-e76b-11f1-b5e7-e284dcf81adb'),(970,'storage.modify:/31f493a3-e76b-11f1-b5e7-e284dcf81adb'),(970,'storage.read:/31f493a3-e76b-11f1-b5e7-e284dcf81adb'),(970,'storage.write:/31f493a3-e76b-11f1-b5e7-e284dcf81adb'),(971,'storage.modify:/31f495ec-e76b-11f1-b5e7-e284dcf81adb'),(971,'storage.read:/31f495ec-e76b-11f1-b5e7-e284dcf81adb'),(971,'storage.write:/31f495ec-e76b-11f1-b5e7-e284dcf81adb'),(972,'storage.modify:/31f4983d-e76b-11f1-b5e7-e284dcf81adb'),(972,'storage.read:/31f4983d-e76b-11f1-b5e7-e284dcf81adb'),(972,'storage.write:/31f4983d-e76b-11f1-b5e7-e284dcf81adb'),(973,'storage.modify:/31f49a84-e76b-11f1-b5e7-e284dcf81adb'),(973,'storage.read:/31f49a84-e76b-11f1-b5e7-e284dcf81adb'),(973,'storage.write:/31f49a84-e76b-11f1-b5e7-e284dcf81adb'),(974,'storage.modify:/31f49ccb-e76b-11f1-b5e7-e284dcf81adb'),(974,'storage.read:/31f49ccb-e76b-11f1-b5e7-e284dcf81adb'),(974,'storage.write:/31f49ccb-e76b-11f1-b5e7-e284dcf81adb'),(975,'storage.modify:/31f49f57-e76b-11f1-b5e7-e284dcf81adb'),(975,'storage.read:/31f49f57-e76b-11f1-b5e7-e284dcf81adb'),(975,'storage.write:/31f49f57-e76b-11f1-b5e7-e284dcf81adb'),(976,'storage.modify:/31f4a1ac-e76b-11f1-b5e7-e284dcf81adb'),(976,'storage.read:/31f4a1ac-e76b-11f1-b5e7-e284dcf81adb'),(976,'storage.write:/31f4a1ac-e76b-11f1-b5e7-e284dcf81adb'),(977,'storage.modify:/31f5db84-e76b-11f1-b5e7-e284dcf81adb'),(977,'storage.read:/31f5db84-e76b-11f1-b5e7-e284dcf81adb'),(977,'storage.write:/31f5db84-e76b-11f1-b5e7-e284dcf81adb'),(978,'storage.modify:/31f5e19a-e76b-11f1-b5e7-e284dcf81adb'),(978,'storage.read:/31f5e19a-e76b-11f1-b5e7-e284dcf81adb'),(978,'storage.write:/31f5e19a-e76b-11f1-b5e7-e284dcf81adb'),(979,'storage.modify:/31f5e428-e76b-11f1-b5e7-e284dcf81adb'),(979,'storage.read:/31f5e428-e76b-11f1-b5e7-e284dcf81adb'),(979,'storage.write:/31f5e428-e76b-11f1-b5e7-e284dcf81adb'),(980,'storage.modify:/31f5e68c-e76b-11f1-b5e7-e284dcf81adb'),(980,'storage.read:/31f5e68c-e76b-11f1-b5e7-e284dcf81adb'),(980,'storage.write:/31f5e68c-e76b-11f1-b5e7-e284dcf81adb'),(981,'storage.modify:/31f5e909-e76b-11f1-b5e7-e284dcf81adb'),(981,'storage.read:/31f5e909-e76b-11f1-b5e7-e284dcf81adb'),(981,'storage.write:/31f5e909-e76b-11f1-b5e7-e284dcf81adb'),(982,'storage.modify:/31f5ec27-e76b-11f1-b5e7-e284dcf81adb'),(982,'storage.read:/31f5ec27-e76b-11f1-b5e7-e284dcf81adb'),(982,'storage.write:/31f5ec27-e76b-11f1-b5e7-e284dcf81adb'),(983,'storage.modify:/31f5ee8e-e76b-11f1-b5e7-e284dcf81adb'),(983,'storage.read:/31f5ee8e-e76b-11f1-b5e7-e284dcf81adb'),(983,'storage.write:/31f5ee8e-e76b-11f1-b5e7-e284dcf81adb'),(984,'storage.modify:/31f5f0da-e76b-11f1-b5e7-e284dcf81adb'),(984,'storage.read:/31f5f0da-e76b-11f1-b5e7-e284dcf81adb'),(984,'storage.write:/31f5f0da-e76b-11f1-b5e7-e284dcf81adb'),(985,'storage.modify:/31f5f328-e76b-11f1-b5e7-e284dcf81adb'),(985,'storage.read:/31f5f328-e76b-11f1-b5e7-e284dcf81adb'),(985,'storage.write:/31f5f328-e76b-11f1-b5e7-e284dcf81adb'),(986,'storage.modify:/31f5f57b-e76b-11f1-b5e7-e284dcf81adb'),(986,'storage.read:/31f5f57b-e76b-11f1-b5e7-e284dcf81adb'),(986,'storage.write:/31f5f57b-e76b-11f1-b5e7-e284dcf81adb'),(987,'storage.modify:/31f5f7c5-e76b-11f1-b5e7-e284dcf81adb'),(987,'storage.read:/31f5f7c5-e76b-11f1-b5e7-e284dcf81adb'),(987,'storage.write:/31f5f7c5-e76b-11f1-b5e7-e284dcf81adb'),(988,'storage.modify:/31f5fa10-e76b-11f1-b5e7-e284dcf81adb'),(988,'storage.read:/31f5fa10-e76b-11f1-b5e7-e284dcf81adb'),(988,'storage.write:/31f5fa10-e76b-11f1-b5e7-e284dcf81adb'),(989,'storage.modify:/31f5fc59-e76b-11f1-b5e7-e284dcf81adb'),(989,'storage.read:/31f5fc59-e76b-11f1-b5e7-e284dcf81adb'),(989,'storage.write:/31f5fc59-e76b-11f1-b5e7-e284dcf81adb'),(990,'storage.modify:/31f5fee5-e76b-11f1-b5e7-e284dcf81adb'),(990,'storage.read:/31f5fee5-e76b-11f1-b5e7-e284dcf81adb'),(990,'storage.write:/31f5fee5-e76b-11f1-b5e7-e284dcf81adb'),(991,'storage.modify:/31f6013e-e76b-11f1-b5e7-e284dcf81adb'),(991,'storage.read:/31f6013e-e76b-11f1-b5e7-e284dcf81adb'),(991,'storage.write:/31f6013e-e76b-11f1-b5e7-e284dcf81adb'),(992,'storage.modify:/31f60393-e76b-11f1-b5e7-e284dcf81adb'),(992,'storage.read:/31f60393-e76b-11f1-b5e7-e284dcf81adb'),(992,'storage.write:/31f60393-e76b-11f1-b5e7-e284dcf81adb'),(993,'storage.modify:/31f605df-e76b-11f1-b5e7-e284dcf81adb'),(993,'storage.read:/31f605df-e76b-11f1-b5e7-e284dcf81adb'),(993,'storage.write:/31f605df-e76b-11f1-b5e7-e284dcf81adb'),(994,'storage.modify:/31f60838-e76b-11f1-b5e7-e284dcf81adb'),(994,'storage.read:/31f60838-e76b-11f1-b5e7-e284dcf81adb'),(994,'storage.write:/31f60838-e76b-11f1-b5e7-e284dcf81adb'),(995,'storage.modify:/31f60a85-e76b-11f1-b5e7-e284dcf81adb'),(995,'storage.read:/31f60a85-e76b-11f1-b5e7-e284dcf81adb'),(995,'storage.write:/31f60a85-e76b-11f1-b5e7-e284dcf81adb'),(996,'storage.modify:/31f60cdd-e76b-11f1-b5e7-e284dcf81adb'),(996,'storage.read:/31f60cdd-e76b-11f1-b5e7-e284dcf81adb'),(996,'storage.write:/31f60cdd-e76b-11f1-b5e7-e284dcf81adb'),(997,'storage.modify:/31f60f33-e76b-11f1-b5e7-e284dcf81adb'),(997,'storage.read:/31f60f33-e76b-11f1-b5e7-e284dcf81adb'),(997,'storage.write:/31f60f33-e76b-11f1-b5e7-e284dcf81adb'),(998,'storage.modify:/31f61181-e76b-11f1-b5e7-e284dcf81adb'),(998,'storage.read:/31f61181-e76b-11f1-b5e7-e284dcf81adb'),(998,'storage.write:/31f61181-e76b-11f1-b5e7-e284dcf81adb'),(999,'storage.modify:/31f613d2-e76b-11f1-b5e7-e284dcf81adb'),(999,'storage.read:/31f613d2-e76b-11f1-b5e7-e284dcf81adb'),(999,'storage.write:/31f613d2-e76b-11f1-b5e7-e284dcf81adb'),(1000,'storage.modify:/31f6161f-e76b-11f1-b5e7-e284dcf81adb'),(1000,'storage.read:/31f6161f-e76b-11f1-b5e7-e284dcf81adb'),(1000,'storage.write:/31f6161f-e76b-11f1-b5e7-e284dcf81adb'),(1001,'storage.modify:/31f61874-e76b-11f1-b5e7-e284dcf81adb'),(1001,'storage.read:/31f61874-e76b-11f1-b5e7-e284dcf81adb'),(1001,'storage.write:/31f61874-e76b-11f1-b5e7-e284dcf81adb'),(1002,'storage.modify:/31f61baa-e76b-11f1-b5e7-e284dcf81adb'),(1002,'storage.read:/31f61baa-e76b-11f1-b5e7-e284dcf81adb'),(1002,'storage.write:/31f61baa-e76b-11f1-b5e7-e284dcf81adb'),(1003,'storage.modify:/31f61e27-e76b-11f1-b5e7-e284dcf81adb'),(1003,'storage.read:/31f61e27-e76b-11f1-b5e7-e284dcf81adb'),(1003,'storage.write:/31f61e27-e76b-11f1-b5e7-e284dcf81adb'),(1004,'storage.modify:/31f62084-e76b-11f1-b5e7-e284dcf81adb'),(1004,'storage.read:/31f62084-e76b-11f1-b5e7-e284dcf81adb'),(1004,'storage.write:/31f62084-e76b-11f1-b5e7-e284dcf81adb'),(1005,'storage.modify:/31f622db-e76b-11f1-b5e7-e284dcf81adb'),(1005,'storage.read:/31f622db-e76b-11f1-b5e7-e284dcf81adb'),(1005,'storage.write:/31f622db-e76b-11f1-b5e7-e284dcf81adb');
/*!40000 ALTER TABLE `iam_scope_policy_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_ssh_key`
--

DROP TABLE IF EXISTS `iam_ssh_key`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_ssh_key` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `fingerprint` varchar(48) NOT NULL,
  `LABEL` varchar(36) NOT NULL,
  `is_primary` tinyint(1) DEFAULT '0',
  `val` longtext,
  `ACCOUNT_ID` bigint DEFAULT NULL,
  `creation_time` datetime NOT NULL,
  `last_update_time` datetime NOT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `fingerprint` (`fingerprint`),
  KEY `FK_iam_ssh_key_ACCOUNT_ID` (`ACCOUNT_ID`),
  CONSTRAINT `FK_iam_ssh_key_ACCOUNT_ID` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_ssh_key`
--

LOCK TABLES `iam_ssh_key` WRITE;
/*!40000 ALTER TABLE `iam_ssh_key` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_ssh_key` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_totp_admin_key`
--

DROP TABLE IF EXISTS `iam_totp_admin_key`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_totp_admin_key` (
  `id` tinyint NOT NULL,
  `admin_mfa_key_hash` varchar(255) NOT NULL,
  `last_update_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `iam_totp_admin_key_chk_1` CHECK ((`id` = 1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_totp_admin_key`
--

LOCK TABLES `iam_totp_admin_key` WRITE;
/*!40000 ALTER TABLE `iam_totp_admin_key` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_totp_admin_key` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_totp_mfa`
--

DROP TABLE IF EXISTS `iam_totp_mfa`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_totp_mfa` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `active` tinyint(1) NOT NULL DEFAULT '0',
  `secret` varchar(255) NOT NULL,
  `creation_time` datetime NOT NULL,
  `last_update_time` datetime NOT NULL,
  `ACCOUNT_ID` bigint DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_totp_mfa_account_id` (`ACCOUNT_ID`),
  CONSTRAINT `FK_iam_totp_mfa_account_id` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_totp_mfa`
--

LOCK TABLES `iam_totp_mfa` WRITE;
/*!40000 ALTER TABLE `iam_totp_mfa` DISABLE KEYS */;
INSERT INTO `iam_totp_mfa` VALUES (1,1,'4S6Jqrvrv4eJDE9va5RkxaVjdjn5FCC958Gysekk1T7eel0pahEbp5iFLENeWZ4VKE1Dzit7AGowmOwD5i5Ma9VjnkdNMnU5WSK58w==','2026-11-23 14:41:08','2026-11-23 14:41:08',1000);
/*!40000 ALTER TABLE `iam_totp_mfa` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_totp_recovery_code`
--

DROP TABLE IF EXISTS `iam_totp_recovery_code`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_totp_recovery_code` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `code` varchar(255) NOT NULL,
  `totp_mfa_id` bigint NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_totp_recovery_code_totp_mfa_id` (`totp_mfa_id`),
  CONSTRAINT `FK_iam_totp_recovery_code_totp_mfa_id` FOREIGN KEY (`totp_mfa_id`) REFERENCES `iam_totp_mfa` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_totp_recovery_code`
--

LOCK TABLES `iam_totp_recovery_code` WRITE;
/*!40000 ALTER TABLE `iam_totp_recovery_code` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_totp_recovery_code` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_user_info`
--

DROP TABLE IF EXISTS `iam_user_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_user_info` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `BIRTHDATE` varchar(255) DEFAULT NULL,
  `EMAIL` varchar(128) NOT NULL,
  `EMAILVERIFIED` tinyint(1) DEFAULT '0',
  `FAMILYNAME` varchar(64) NOT NULL,
  `GENDER` varchar(255) DEFAULT NULL,
  `GIVENNAME` varchar(64) NOT NULL,
  `LOCALE` varchar(255) DEFAULT NULL,
  `MIDDLENAME` varchar(64) DEFAULT NULL,
  `NICKNAME` varchar(255) DEFAULT NULL,
  `PHONENUMBER` varchar(255) DEFAULT NULL,
  `PHONENUMBERVERIFIED` tinyint(1) DEFAULT '0',
  `PICTURE` varchar(255) DEFAULT NULL,
  `PROFILE` varchar(255) DEFAULT NULL,
  `WEBSITE` varchar(255) DEFAULT NULL,
  `ZONEINFO` varchar(255) DEFAULT NULL,
  `ADDRESS_ID` bigint DEFAULT NULL,
  `DTYPE` varchar(31) DEFAULT NULL,
  `affiliation` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `iui_em_idx` (`EMAIL`),
  KEY `iui_gn_fn_idx` (`GIVENNAME`,`FAMILYNAME`),
  KEY `FK_iam_user_info_address_id` (`ADDRESS_ID`),
  CONSTRAINT `FK_iam_user_info_address_id` FOREIGN KEY (`ADDRESS_ID`) REFERENCES `iam_address` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2001 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_user_info`
--

LOCK TABLES `iam_user_info` WRITE;
/*!40000 ALTER TABLE `iam_user_info` DISABLE KEYS */;
INSERT INTO `iam_user_info` VALUES (1,'1950-01-01','1_admin@iam.test',1,'User','M','Admin',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(2,'1950-01-01','test@iam.test',1,'User','M','Test',NULL,NULL,'test',NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,'indigo'),(3,'1950-01-01','3_admin@iam.test',1,'Email 0','M','Duplicate',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(4,'1950-01-01','4_duplicate@iam.test',1,'Email 1','M','Duplicate ',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(5,'1950-01-01','5_duplicate@iam.test',1,'Email 2','M','Duplicate ',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(10,NULL,'prod.manager@iam.test',1,'Manager',NULL,'Production',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,'INFN-CNAF'),(100,NULL,'test-100@test.org',1,'User',NULL,'Test-100',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(101,NULL,'test-101@test.org',1,'User',NULL,'Test-101',NULL,'middlename-101',NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(102,NULL,'test-102@test.org',1,'User',NULL,'Test-102',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(103,NULL,'test-103@test.org',1,'User',NULL,'Test-103',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(104,NULL,'test-104@test.org',1,'User',NULL,'Test-104',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(105,NULL,'test-105@test.org',1,'User',NULL,'Test-105',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(106,NULL,'test-106@test.org',1,'User',NULL,'Test-106',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(107,NULL,'test-107@test.org',1,'User',NULL,'Test-107',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(108,NULL,'test-108@test.org',1,'User',NULL,'Test-108',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(109,NULL,'test-109@test.org',1,'User',NULL,'Test-109',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(110,NULL,'test-110@test.org',1,'User',NULL,'Test-110',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(111,NULL,'test-111@test.org',1,'User',NULL,'Test-111',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(112,NULL,'test-112@test.org',1,'User',NULL,'Test-112',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(113,NULL,'test-113@test.org',1,'User',NULL,'Test-113',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(114,NULL,'test-114@test.org',1,'User',NULL,'Test-114',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(115,NULL,'test-115@test.org',1,'User',NULL,'Test-115',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(116,NULL,'test-116@test.org',1,'User',NULL,'Test-116',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(117,NULL,'test-117@test.org',1,'User',NULL,'Test-117',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(118,NULL,'test-118@test.org',1,'User',NULL,'Test-118',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(119,NULL,'test-119@test.org',1,'User',NULL,'Test-119',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(120,NULL,'test-120@test.org',1,'User',NULL,'Test-120',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(121,NULL,'test-121@test.org',1,'User',NULL,'Test-121',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(122,NULL,'test-122@test.org',1,'User',NULL,'Test-122',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(123,NULL,'test-123@test.org',1,'User',NULL,'Test-123',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(124,NULL,'test-124@test.org',1,'User',NULL,'Test-124',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(125,NULL,'test-125@test.org',1,'User',NULL,'Test-125',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(126,NULL,'test-126@test.org',1,'User',NULL,'Test-126',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(127,NULL,'test-127@test.org',1,'User',NULL,'Test-127',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(128,NULL,'test-128@test.org',1,'User',NULL,'Test-128',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(129,NULL,'test-129@test.org',1,'User',NULL,'Test-129',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(130,NULL,'test-130@test.org',1,'User',NULL,'Test-130',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(131,NULL,'test-131@test.org',1,'User',NULL,'Test-131',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(132,NULL,'test-132@test.org',1,'User',NULL,'Test-132',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(133,NULL,'test-133@test.org',1,'User',NULL,'Test-133',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(134,NULL,'test-134@test.org',1,'User',NULL,'Test-134',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(135,NULL,'test-135@test.org',1,'User',NULL,'Test-135',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(136,NULL,'test-136@test.org',1,'User',NULL,'Test-136',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(137,NULL,'test-137@test.org',1,'User',NULL,'Test-137',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(138,NULL,'test-138@test.org',1,'User',NULL,'Test-138',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(139,NULL,'test-139@test.org',1,'User',NULL,'Test-139',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(140,NULL,'test-140@test.org',1,'User',NULL,'Test-140',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(141,NULL,'test-141@test.org',1,'User',NULL,'Test-141',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(142,NULL,'test-142@test.org',1,'User',NULL,'Test-142',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(143,NULL,'test-143@test.org',1,'User',NULL,'Test-143',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(144,NULL,'test-144@test.org',1,'User',NULL,'Test-144',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(145,NULL,'test-145@test.org',1,'User',NULL,'Test-145',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(146,NULL,'test-146@test.org',1,'User',NULL,'Test-146',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(147,NULL,'test-147@test.org',1,'User',NULL,'Test-147',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(148,NULL,'test-148@test.org',1,'User',NULL,'Test-148',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(149,NULL,'test-149@test.org',1,'User',NULL,'Test-149',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(150,NULL,'test-150@test.org',1,'User',NULL,'Test-150',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(151,NULL,'test-151@test.org',1,'User',NULL,'Test-151',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(152,NULL,'test-152@test.org',1,'User',NULL,'Test-152',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(153,NULL,'test-153@test.org',1,'User',NULL,'Test-153',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(154,NULL,'test-154@test.org',1,'User',NULL,'Test-154',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(155,NULL,'test-155@test.org',1,'User',NULL,'Test-155',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(156,NULL,'test-156@test.org',1,'User',NULL,'Test-156',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(157,NULL,'test-157@test.org',1,'User',NULL,'Test-157',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(158,NULL,'test-158@test.org',1,'User',NULL,'Test-158',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(159,NULL,'test-159@test.org',1,'User',NULL,'Test-159',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(160,NULL,'test-160@test.org',1,'User',NULL,'Test-160',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(161,NULL,'test-161@test.org',1,'User',NULL,'Test-161',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(162,NULL,'test-162@test.org',1,'User',NULL,'Test-162',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(163,NULL,'test-163@test.org',1,'User',NULL,'Test-163',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(164,NULL,'test-164@test.org',1,'User',NULL,'Test-164',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(165,NULL,'test-165@test.org',1,'User',NULL,'Test-165',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(166,NULL,'test-166@test.org',1,'User',NULL,'Test-166',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(167,NULL,'test-167@test.org',1,'User',NULL,'Test-167',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(168,NULL,'test-168@test.org',1,'User',NULL,'Test-168',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(169,NULL,'test-169@test.org',1,'User',NULL,'Test-169',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(170,NULL,'test-170@test.org',1,'User',NULL,'Test-170',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(171,NULL,'test-171@test.org',1,'User',NULL,'Test-171',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(172,NULL,'test-172@test.org',1,'User',NULL,'Test-172',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(173,NULL,'test-173@test.org',1,'User',NULL,'Test-173',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(174,NULL,'test-174@test.org',1,'User',NULL,'Test-174',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(175,NULL,'test-175@test.org',1,'User',NULL,'Test-175',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(176,NULL,'test-176@test.org',1,'User',NULL,'Test-176',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(177,NULL,'test-177@test.org',1,'User',NULL,'Test-177',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(178,NULL,'test-178@test.org',1,'User',NULL,'Test-178',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(179,NULL,'test-179@test.org',1,'User',NULL,'Test-179',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(180,NULL,'test-180@test.org',1,'User',NULL,'Test-180',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(181,NULL,'test-181@test.org',1,'User',NULL,'Test-181',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(182,NULL,'test-182@test.org',1,'User',NULL,'Test-182',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(183,NULL,'test-183@test.org',1,'User',NULL,'Test-183',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(184,NULL,'test-184@test.org',1,'User',NULL,'Test-184',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(185,NULL,'test-185@test.org',1,'User',NULL,'Test-185',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(186,NULL,'test-186@test.org',1,'User',NULL,'Test-186',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(187,NULL,'test-187@test.org',1,'User',NULL,'Test-187',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(188,NULL,'test-188@test.org',1,'User',NULL,'Test-188',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(189,NULL,'test-189@test.org',1,'User',NULL,'Test-189',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(190,NULL,'test-190@test.org',1,'User',NULL,'Test-190',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(191,NULL,'test-191@test.org',1,'User',NULL,'Test-191',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(192,NULL,'test-192@test.org',1,'User',NULL,'Test-192',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(193,NULL,'test-193@test.org',1,'User',NULL,'Test-193',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(194,NULL,'test-194@test.org',1,'User',NULL,'Test-194',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(195,NULL,'test-195@test.org',1,'User',NULL,'Test-195',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(196,NULL,'test-196@test.org',1,'User',NULL,'Test-196',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(197,NULL,'test-197@test.org',1,'User',NULL,'Test-197',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(198,NULL,'test-198@test.org',1,'User',NULL,'Test-198',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(199,NULL,'test-199@test.org',1,'User',NULL,'Test-199',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(200,NULL,'test-200@test.org',1,'User',NULL,'Test-200',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(201,NULL,'test-201@test.org',1,'User',NULL,'Test-201',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(202,NULL,'test-202@test.org',1,'User',NULL,'Test-202',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(203,NULL,'test-203@test.org',1,'User',NULL,'Test-203',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(204,NULL,'test-204@test.org',1,'User',NULL,'Test-204',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(205,NULL,'test-205@test.org',1,'User',NULL,'Test-205',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(206,NULL,'test-206@test.org',1,'User',NULL,'Test-206',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(207,NULL,'test-207@test.org',1,'User',NULL,'Test-207',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(208,NULL,'test-208@test.org',1,'User',NULL,'Test-208',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(209,NULL,'test-209@test.org',1,'User',NULL,'Test-209',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(210,NULL,'test-210@test.org',1,'User',NULL,'Test-210',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(211,NULL,'test-211@test.org',1,'User',NULL,'Test-211',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(212,NULL,'test-212@test.org',1,'User',NULL,'Test-212',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(213,NULL,'test-213@test.org',1,'User',NULL,'Test-213',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(214,NULL,'test-214@test.org',1,'User',NULL,'Test-214',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(215,NULL,'test-215@test.org',1,'User',NULL,'Test-215',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(216,NULL,'test-216@test.org',1,'User',NULL,'Test-216',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(217,NULL,'test-217@test.org',1,'User',NULL,'Test-217',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(218,NULL,'test-218@test.org',1,'User',NULL,'Test-218',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(219,NULL,'test-219@test.org',1,'User',NULL,'Test-219',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(220,NULL,'test-220@test.org',1,'User',NULL,'Test-220',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(221,NULL,'test-221@test.org',1,'User',NULL,'Test-221',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(222,NULL,'test-222@test.org',1,'User',NULL,'Test-222',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(223,NULL,'test-223@test.org',1,'User',NULL,'Test-223',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(224,NULL,'test-224@test.org',1,'User',NULL,'Test-224',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(225,NULL,'test-225@test.org',1,'User',NULL,'Test-225',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(226,NULL,'test-226@test.org',1,'User',NULL,'Test-226',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(227,NULL,'test-227@test.org',1,'User',NULL,'Test-227',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(228,NULL,'test-228@test.org',1,'User',NULL,'Test-228',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(229,NULL,'test-229@test.org',1,'User',NULL,'Test-229',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(230,NULL,'test-230@test.org',1,'User',NULL,'Test-230',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(231,NULL,'test-231@test.org',1,'User',NULL,'Test-231',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(232,NULL,'test-232@test.org',1,'User',NULL,'Test-232',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(233,NULL,'test-233@test.org',1,'User',NULL,'Test-233',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(234,NULL,'test-234@test.org',1,'User',NULL,'Test-234',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(235,NULL,'test-235@test.org',1,'User',NULL,'Test-235',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(236,NULL,'test-236@test.org',1,'User',NULL,'Test-236',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(237,NULL,'test-237@test.org',1,'User',NULL,'Test-237',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(238,NULL,'test-238@test.org',1,'User',NULL,'Test-238',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(239,NULL,'test-239@test.org',1,'User',NULL,'Test-239',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(240,NULL,'test-240@test.org',1,'User',NULL,'Test-240',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(241,NULL,'test-241@test.org',1,'User',NULL,'Test-241',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(242,NULL,'test-242@test.org',1,'User',NULL,'Test-242',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(243,NULL,'test-243@test.org',1,'User',NULL,'Test-243',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(244,NULL,'test-244@test.org',1,'User',NULL,'Test-244',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(245,NULL,'test-245@test.org',1,'User',NULL,'Test-245',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(246,NULL,'test-246@test.org',1,'User',NULL,'Test-246',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(247,NULL,'test-247@test.org',1,'User',NULL,'Test-247',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(248,NULL,'test-248@test.org',1,'User',NULL,'Test-248',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(249,NULL,'test-249@test.org',1,'User',NULL,'Test-249',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(250,NULL,'test-250@test.org',1,'User',NULL,'Test-250',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(251,NULL,'test-251@test.org',1,'User',NULL,'Test-251',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(252,NULL,'test-252@test.org',1,'User',NULL,'Test-252',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(253,NULL,'test-253@test.org',1,'User',NULL,'Test-253',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(254,NULL,'test-254@test.org',1,'User',NULL,'Test-254',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(255,NULL,'test-255@test.org',1,'User',NULL,'Test-255',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(256,NULL,'test-256@test.org',1,'User',NULL,'Test-256',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(257,NULL,'test-257@test.org',1,'User',NULL,'Test-257',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(258,NULL,'test-258@test.org',1,'User',NULL,'Test-258',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(259,NULL,'test-259@test.org',1,'User',NULL,'Test-259',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(260,NULL,'test-260@test.org',1,'User',NULL,'Test-260',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(261,NULL,'test-261@test.org',1,'User',NULL,'Test-261',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(262,NULL,'test-262@test.org',1,'User',NULL,'Test-262',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(263,NULL,'test-263@test.org',1,'User',NULL,'Test-263',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(264,NULL,'test-264@test.org',1,'User',NULL,'Test-264',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(265,NULL,'test-265@test.org',1,'User',NULL,'Test-265',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(266,NULL,'test-266@test.org',1,'User',NULL,'Test-266',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(267,NULL,'test-267@test.org',1,'User',NULL,'Test-267',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(268,NULL,'test-268@test.org',1,'User',NULL,'Test-268',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(269,NULL,'test-269@test.org',1,'User',NULL,'Test-269',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(270,NULL,'test-270@test.org',1,'User',NULL,'Test-270',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(271,NULL,'test-271@test.org',1,'User',NULL,'Test-271',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(272,NULL,'test-272@test.org',1,'User',NULL,'Test-272',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(273,NULL,'test-273@test.org',1,'User',NULL,'Test-273',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(274,NULL,'test-274@test.org',1,'User',NULL,'Test-274',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(275,NULL,'test-275@test.org',1,'User',NULL,'Test-275',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(276,NULL,'test-276@test.org',1,'User',NULL,'Test-276',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(277,NULL,'test-277@test.org',1,'User',NULL,'Test-277',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(278,NULL,'test-278@test.org',1,'User',NULL,'Test-278',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(279,NULL,'test-279@test.org',1,'User',NULL,'Test-279',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(280,NULL,'test-280@test.org',1,'User',NULL,'Test-280',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(281,NULL,'test-281@test.org',1,'User',NULL,'Test-281',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(282,NULL,'test-282@test.org',1,'User',NULL,'Test-282',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(283,NULL,'test-283@test.org',1,'User',NULL,'Test-283',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(284,NULL,'test-284@test.org',1,'User',NULL,'Test-284',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(285,NULL,'test-285@test.org',1,'User',NULL,'Test-285',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(286,NULL,'test-286@test.org',1,'User',NULL,'Test-286',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(287,NULL,'test-287@test.org',1,'User',NULL,'Test-287',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(288,NULL,'test-288@test.org',1,'User',NULL,'Test-288',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(289,NULL,'test-289@test.org',1,'User',NULL,'Test-289',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(290,NULL,'test-290@test.org',1,'User',NULL,'Test-290',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(291,NULL,'test-291@test.org',1,'User',NULL,'Test-291',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(292,NULL,'test-292@test.org',1,'User',NULL,'Test-292',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(293,NULL,'test-293@test.org',1,'User',NULL,'Test-293',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(294,NULL,'test-294@test.org',1,'User',NULL,'Test-294',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(295,NULL,'test-295@test.org',1,'User',NULL,'Test-295',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(296,NULL,'test-296@test.org',1,'User',NULL,'Test-296',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(297,NULL,'test-297@test.org',1,'User',NULL,'Test-297',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(298,NULL,'test-298@test.org',1,'User',NULL,'Test-298',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(299,NULL,'test-299@test.org',1,'User',NULL,'Test-299',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(300,NULL,'test-300@test.org',1,'User',NULL,'Test-300',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(301,NULL,'test-301@test.org',1,'User',NULL,'Test-301',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(302,NULL,'test-302@test.org',1,'User',NULL,'Test-302',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(303,NULL,'test-303@test.org',1,'User',NULL,'Test-303',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(304,NULL,'test-304@test.org',1,'User',NULL,'Test-304',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(305,NULL,'test-305@test.org',1,'User',NULL,'Test-305',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(306,NULL,'test-306@test.org',1,'User',NULL,'Test-306',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(307,NULL,'test-307@test.org',1,'User',NULL,'Test-307',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(308,NULL,'test-308@test.org',1,'User',NULL,'Test-308',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(309,NULL,'test-309@test.org',1,'User',NULL,'Test-309',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(310,NULL,'test-310@test.org',1,'User',NULL,'Test-310',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(311,NULL,'test-311@test.org',1,'User',NULL,'Test-311',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(312,NULL,'test-312@test.org',1,'User',NULL,'Test-312',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(313,NULL,'test-313@test.org',1,'User',NULL,'Test-313',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(314,NULL,'test-314@test.org',1,'User',NULL,'Test-314',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(315,NULL,'test-315@test.org',1,'User',NULL,'Test-315',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(316,NULL,'test-316@test.org',1,'User',NULL,'Test-316',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(317,NULL,'test-317@test.org',1,'User',NULL,'Test-317',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(318,NULL,'test-318@test.org',1,'User',NULL,'Test-318',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(319,NULL,'test-319@test.org',1,'User',NULL,'Test-319',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(320,NULL,'test-320@test.org',1,'User',NULL,'Test-320',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(321,NULL,'test-321@test.org',1,'User',NULL,'Test-321',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(322,NULL,'test-322@test.org',1,'User',NULL,'Test-322',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(323,NULL,'test-323@test.org',1,'User',NULL,'Test-323',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(324,NULL,'test-324@test.org',1,'User',NULL,'Test-324',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(325,NULL,'test-325@test.org',1,'User',NULL,'Test-325',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(326,NULL,'test-326@test.org',1,'User',NULL,'Test-326',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(327,NULL,'test-327@test.org',1,'User',NULL,'Test-327',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(328,NULL,'test-328@test.org',1,'User',NULL,'Test-328',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(329,NULL,'test-329@test.org',1,'User',NULL,'Test-329',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(330,NULL,'test-330@test.org',1,'User',NULL,'Test-330',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(331,NULL,'test-331@test.org',1,'User',NULL,'Test-331',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(332,NULL,'test-332@test.org',1,'User',NULL,'Test-332',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(333,NULL,'test-333@test.org',1,'User',NULL,'Test-333',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(334,NULL,'test-334@test.org',1,'User',NULL,'Test-334',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(335,NULL,'test-335@test.org',1,'User',NULL,'Test-335',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(336,NULL,'test-336@test.org',1,'User',NULL,'Test-336',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(337,NULL,'test-337@test.org',1,'User',NULL,'Test-337',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(338,NULL,'test-338@test.org',1,'User',NULL,'Test-338',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(339,NULL,'test-339@test.org',1,'User',NULL,'Test-339',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(340,NULL,'test-340@test.org',1,'User',NULL,'Test-340',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(341,NULL,'test-341@test.org',1,'User',NULL,'Test-341',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(342,NULL,'test-342@test.org',1,'User',NULL,'Test-342',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(343,NULL,'test-343@test.org',1,'User',NULL,'Test-343',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(344,NULL,'test-344@test.org',1,'User',NULL,'Test-344',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(345,NULL,'test-345@test.org',1,'User',NULL,'Test-345',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(346,NULL,'test-346@test.org',1,'User',NULL,'Test-346',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(347,NULL,'test-347@test.org',1,'User',NULL,'Test-347',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(1000,'2000-01-01','testwithmfa@iam.test',1,'MFA','F','Test',NULL,NULL,'testwithmfa',NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,'indigo'),(2000,NULL,'unverified@another.test',0,'Unverified',NULL,'User',NULL,NULL,'unverified',NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,'unknown affiliation');
/*!40000 ALTER TABLE `iam_user_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_x509_cert`
--

DROP TABLE IF EXISTS `iam_x509_cert`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_x509_cert` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `subject_dn` varchar(256) CHARACTER SET latin1 COLLATE latin1_general_cs DEFAULT NULL,
  `LABEL` varchar(36) NOT NULL,
  `is_primary` tinyint(1) DEFAULT '0',
  `ACCOUNT_ID` bigint DEFAULT NULL,
  `CERTIFICATE` text,
  `issuer_dn` varchar(256) CHARACTER SET latin1 COLLATE latin1_general_cs DEFAULT NULL,
  `creation_time` datetime NOT NULL,
  `last_update_time` datetime NOT NULL,
  `proxy_id` bigint DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `idx_iam_x509_cert_cerificate` (`CERTIFICATE`(256)),
  KEY `FK_iam_x509_cert_ACCOUNT_ID` (`ACCOUNT_ID`),
  KEY `FK_iam_x509_cert_proxy_id` (`proxy_id`),
  KEY `idx_subject_dn` (`subject_dn`),
  CONSTRAINT `FK_iam_x509_cert_ACCOUNT_ID` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_x509_cert_proxy_id` FOREIGN KEY (`proxy_id`) REFERENCES `iam_x509_proxy` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_x509_cert`
--

LOCK TABLES `iam_x509_cert` WRITE;
/*!40000 ALTER TABLE `iam_x509_cert` DISABLE KEYS */;
INSERT INTO `iam_x509_cert` VALUES (1,'CN=test2,O=IGI,C=IT','test2 cert',1,1,'-----BEGIN CERTIFICATE-----\nMIIDnjCCAoagAwIBAgIBCzANBgkqhkiG9w0BAQUFADAtMQswCQYDVQQGEwJJVDEM\nMAoGA1UECgwDSUdJMRAwDgYDVQQDDAdUZXN0IENBMB4XDTEyMDkyNjE1MzkzOFoX\nDTIyMDkyNDE1MzkzOFowKzELMAkGA1UEBhMCSVQxDDAKBgNVBAoTA0lHSTEOMAwG\nA1UEAxMFdGVzdDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEYYwo\neq5ucXGsIZqI5V30OmEZTLzz3TCtFSp+DWbFHAeiiZNNktK44udHV+kwTjSxHTUJ\nP9RIvCAIMggtvibesXrTp1UHAF6p1d2GaUmU+mc/y7zRESxuSXx+SqWCwBOVxOzj\nDhm9oWlg3TSNctV2qv0HR2t8hsnfsQShULwaUJmQZ1fBfDN6HL5ITe77ptXB84Hz\nMAmNv0ckoQmVGtlVhoasppTgMhoWvBSguT1FGw7A/a8ZzQZV8rC1BP/1LZtRitHm\nstErUyULBjQekpu3VhGFJLCFD3fcyjoBKsIxCm62NhzHLOF8RE+kW05MRGrUu007\nCuV3yCDZOixIAxKVAgMBAAGjgcowgccwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU\nXNkN/hv+aBr6hqNqYm1VaiEAvpcwDgYDVR0PAQH/BAQDAgXgMD4GA1UdJQQ3MDUG\nCCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBBggrBgEF\nBQcDBDAfBgNVHSMEGDAWgBSRdzZ7LrRp8yfqt/YIi0ojohFJxjAnBgNVHREEIDAe\ngRxhbmRyZWEuY2VjY2FudGlAY25hZi5pbmZuLml0MA0GCSqGSIb3DQEBBQUAA4IB\nAQBOavmIRcBqWnGFmcEp8zJ+cR3k02UcM0Xg7/vAnxJ7JziniMJLyBrxAaW1j2f6\nqJrap9rK+aukhovInTSrdWKM6y5ceY0w7u4nsu8Y3lRf3g9e766iuY3NfflDZE2N\ns3JuHZljwx7NGEOrr/Wi5Q1g9JVJcK+A+aB3vPLoS/Uc95ibdqJKHVG0rcKLnqR6\nAVvzyPxJtpwk4yy4V+juBZib2SImBWJ7C5VHuHLMAOxtNV84CIXpdvLKfA1Bjf3W\nUMrcvhN03L72j9IR0WEZlFMfYbxv1gbNbo+fhVo3itHI3lTl0K0BD5bOP0LqtARL\ngZ9zFVlxWHcKUqQ41ZQXNg7U\n-----END CERTIFICATE-----','CN=Test CA,O=IGI,C=IT','2026-11-23 14:41:08','2026-11-23 14:41:08',NULL);
/*!40000 ALTER TABLE `iam_x509_cert` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_x509_proxy`
--

DROP TABLE IF EXISTS `iam_x509_proxy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `iam_x509_proxy` (
  `ID` bigint NOT NULL AUTO_INCREMENT,
  `CHAIN` longtext NOT NULL,
  `exp_time` datetime NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_IAM_X509_PXY_EXP_T` (`exp_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_x509_proxy`
--

LOCK TABLES `iam_x509_proxy` WRITE;
/*!40000 ALTER TABLE `iam_x509_proxy` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_x509_proxy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pairwise_identifier`
--

DROP TABLE IF EXISTS `pairwise_identifier`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pairwise_identifier` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `identifier` varchar(256) DEFAULT NULL,
  `sub` varchar(256) DEFAULT NULL,
  `sector_identifier` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pairwise_identifier`
--

LOCK TABLES `pairwise_identifier` WRITE;
/*!40000 ALTER TABLE `pairwise_identifier` DISABLE KEYS */;
/*!40000 ALTER TABLE `pairwise_identifier` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `permission`
--

DROP TABLE IF EXISTS `permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `resource_set_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `permission`
--

LOCK TABLES `permission` WRITE;
/*!40000 ALTER TABLE `permission` DISABLE KEYS */;
/*!40000 ALTER TABLE `permission` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `permission_scope`
--

DROP TABLE IF EXISTS `permission_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_scope` (
  `owner_id` bigint NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `permission_scope`
--

LOCK TABLES `permission_scope` WRITE;
/*!40000 ALTER TABLE `permission_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `permission_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `permission_ticket`
--

DROP TABLE IF EXISTS `permission_ticket`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_ticket` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `ticket` varchar(256) NOT NULL,
  `permission_id` bigint NOT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `permission_ticket`
--

LOCK TABLES `permission_ticket` WRITE;
/*!40000 ALTER TABLE `permission_ticket` DISABLE KEYS */;
/*!40000 ALTER TABLE `permission_ticket` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `policy`
--

DROP TABLE IF EXISTS `policy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) DEFAULT NULL,
  `resource_set_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `policy`
--

LOCK TABLES `policy` WRITE;
/*!40000 ALTER TABLE `policy` DISABLE KEYS */;
/*!40000 ALTER TABLE `policy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `policy_scope`
--

DROP TABLE IF EXISTS `policy_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `policy_scope` (
  `owner_id` bigint NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `policy_scope`
--

LOCK TABLES `policy_scope` WRITE;
/*!40000 ALTER TABLE `policy_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `policy_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `refresh_token`
--

DROP TABLE IF EXISTS `refresh_token`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `refresh_token` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `token_value` varchar(4096) DEFAULT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  `auth_holder_id` bigint DEFAULT NULL,
  `client_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `rt_tvh_idx` (`token_value`(767)),
  KEY `rf_ahi_idx` (`auth_holder_id`),
  KEY `FK_refresh_token_client_id` (`client_id`),
  CONSTRAINT `FK_refresh_token_auth_holder_id` FOREIGN KEY (`auth_holder_id`) REFERENCES `authentication_holder` (`id`) ON DELETE CASCADE,
  CONSTRAINT `FK_refresh_token_client_id` FOREIGN KEY (`client_id`) REFERENCES `client_details` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `refresh_token`
--

LOCK TABLES `refresh_token` WRITE;
/*!40000 ALTER TABLE `refresh_token` DISABLE KEYS */;
INSERT INTO `refresh_token` VALUES (1,'eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2lhbS5sb2NhbC5pby8iLCJleHAiOjE3OTU1MzEzODEsImlhdCI6MTc5NTQ0NDk4MSwianRpIjoiNzE5ZmNjOGEtZmEwYi00NjUzLThhYWQtZmY1OTE0MDMwNGQxIn0.','2026-11-24 14:43:02',2,1),(2,'eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2lhbS5sb2NhbC5pby8iLCJpYXQiOjE3OTU0NDU5OTUsImp0aSI6IjUzZjE5MjIwLWRjMWItNDBiNS1iOTM5LWU0YTc4YzE4ZTBkZSJ9.',NULL,4,1);
/*!40000 ALTER TABLE `refresh_token` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resource_set`
--

DROP TABLE IF EXISTS `resource_set`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `resource_set` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) NOT NULL,
  `uri` varchar(1024) DEFAULT NULL,
  `icon_uri` varchar(1024) DEFAULT NULL,
  `rs_type` varchar(256) DEFAULT NULL,
  `owner` varchar(256) NOT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resource_set`
--

LOCK TABLES `resource_set` WRITE;
/*!40000 ALTER TABLE `resource_set` DISABLE KEYS */;
/*!40000 ALTER TABLE `resource_set` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resource_set_scope`
--

DROP TABLE IF EXISTS `resource_set_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `resource_set_scope` (
  `owner_id` bigint NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `resource_set_scope`
--

LOCK TABLES `resource_set_scope` WRITE;
/*!40000 ALTER TABLE `resource_set_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `resource_set_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `saved_registered_client`
--

DROP TABLE IF EXISTS `saved_registered_client`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_registered_client` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `issuer` varchar(1024) DEFAULT NULL,
  `registered_client` varchar(8192) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `saved_registered_client`
--

LOCK TABLES `saved_registered_client` WRITE;
/*!40000 ALTER TABLE `saved_registered_client` DISABLE KEYS */;
/*!40000 ALTER TABLE `saved_registered_client` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `saved_user_auth`
--

DROP TABLE IF EXISTS `saved_user_auth`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_user_auth` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) DEFAULT NULL,
  `authenticated` tinyint(1) DEFAULT NULL,
  `source_class` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `saved_user_auth`
--

LOCK TABLES `saved_user_auth` WRITE;
/*!40000 ALTER TABLE `saved_user_auth` DISABLE KEYS */;
INSERT INTO `saved_user_auth` VALUES (1,'admin',1,'it.infn.mw.iam.core.ExtendedAuthenticationToken'),(2,'admin',1,'it.infn.mw.iam.core.ExtendedAuthenticationToken'),(3,'test',1,'it.infn.mw.iam.core.ExtendedAuthenticationToken'),(4,'test',1,'it.infn.mw.iam.core.ExtendedAuthenticationToken');
/*!40000 ALTER TABLE `saved_user_auth` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `saved_user_auth_authority`
--

DROP TABLE IF EXISTS `saved_user_auth_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_user_auth_authority` (
  `owner_id` bigint DEFAULT NULL,
  `authority` varchar(256) DEFAULT NULL,
  KEY `suaa_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `saved_user_auth_authority`
--

LOCK TABLES `saved_user_auth_authority` WRITE;
/*!40000 ALTER TABLE `saved_user_auth_authority` DISABLE KEYS */;
INSERT INTO `saved_user_auth_authority` VALUES (1,'ROLE_USER'),(1,'ROLE_ADMIN'),(2,'ROLE_USER'),(2,'ROLE_ADMIN'),(3,'ROLE_USER'),(4,'ROLE_USER');
/*!40000 ALTER TABLE `saved_user_auth_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `saved_user_auth_info`
--

DROP TABLE IF EXISTS `saved_user_auth_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `saved_user_auth_info` (
  `owner_id` bigint DEFAULT NULL,
  `info_key` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `info_val` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  UNIQUE KEY `owner_id` (`owner_id`,`info_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `saved_user_auth_info`
--

LOCK TABLES `saved_user_auth_info` WRITE;
/*!40000 ALTER TABLE `saved_user_auth_info` DISABLE KEYS */;
/*!40000 ALTER TABLE `saved_user_auth_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `schema_version`
--

DROP TABLE IF EXISTS `schema_version`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `schema_version` (
  `installed_rank` int NOT NULL,
  `version` varchar(50) DEFAULT NULL,
  `description` varchar(200) NOT NULL,
  `type` varchar(20) NOT NULL,
  `script` varchar(1000) NOT NULL,
  `checksum` int DEFAULT NULL,
  `installed_by` varchar(100) NOT NULL,
  `installed_on` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `execution_time` int NOT NULL,
  `success` tinyint(1) NOT NULL,
  PRIMARY KEY (`installed_rank`),
  KEY `schema_version_s_idx` (`success`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `schema_version`
--

LOCK TABLES `schema_version` WRITE;
/*!40000 ALTER TABLE `schema_version` DISABLE KEYS */;
INSERT INTO `schema_version` VALUES (1,'1',' init','SQL','V1___init.sql',-673105977,'iam','2026-11-23 14:40:41',3719,1),(2,'2',' iam tables','SQL','V2___iam_tables.sql',916872168,'iam','2026-11-23 14:40:43',2437,1),(3,'3','basic configuration','SQL','V3__basic_configuration.sql',-1952954691,'iam','2026-11-23 14:40:43',4,1),(4,'3.1',' duplicate email user','SQL','V3_1___duplicate_email_user.sql',-754234138,'iam','2026-11-23 14:40:43',4,1),(5,'4',' x509 updates','SQL','V4___x509_updates.sql',803590936,'iam','2026-11-23 14:40:43',46,1),(6,'5',' registration request','SQL','V5___registration_request.sql',844204664,'iam','2026-11-23 14:40:44',334,1),(7,'6',' remove wrong constraints','SQL','V6___remove_wrong_constraints.sql',2003434964,'iam','2026-11-23 14:40:44',81,1),(8,'7',' notification tables','SQL','V7___notification_tables.sql',-1136933843,'iam','2026-11-23 14:40:45',680,1),(9,'8',' mitre update','SQL','V8___mitre_update.sql',608617254,'iam','2026-11-23 14:40:45',49,1),(10,'9','mitre saved user authn changes','SQL','V9__mitre_saved_user_authn_changes.sql',302744444,'iam','2026-11-23 14:40:45',83,1),(11,'10','fix internal authz scopes','SQL','V10__fix_internal_authz_scopes.sql',-686432566,'iam','2026-11-23 14:40:45',2,1),(12,'10.1','Password Update','JDBC','db.migration.mysql.V10_1__Password_Update',NULL,'iam','2026-11-23 14:40:45',584,1),(13,'10.2',' CheckDuplicateEmails','JDBC','db.migration.mysql.V10_2___CheckDuplicateEmails',NULL,'iam','2026-11-23 14:40:45',6,1),(14,'11','fix base scim and reg scopes','SQL','V11__fix_base_scim_and_reg_scopes.sql',-2106952067,'iam','2026-11-23 14:40:45',1,1),(15,'11.1','no attr id saml account for admin user','SQL','V11_1__no_attr_id_saml_account_for_admin_user.sql',-448912898,'iam','2026-11-23 14:40:45',2,1),(16,'12','iam group nested groups','SQL','V12__iam_group_nested_groups.sql',-2140651111,'iam','2026-11-23 14:40:46',282,1),(17,'13','add attribute id to saml id table','SQL','V13__add_attribute_id_to_saml_id_table.sql',681840221,'iam','2026-11-23 14:40:46',341,1),(18,'14',' x509 certs table changes','SQL','V14___x509_certs_table_changes.sql',-310236366,'iam','2026-11-23 14:40:47',682,1),(19,'15','alter iam group','SQL','V15__alter_iam_group.sql',588116562,'iam','2026-11-23 14:40:47',24,1),(20,'16','add provisioned column to iam account','SQL','V16__add_provisioned_column_to_iam_account.sql',448586794,'iam','2026-11-23 14:40:47',357,1),(21,'17','add scope policy tables','SQL','V17__add_scope_policy_tables.sql',460278210,'iam','2026-11-23 14:40:48',822,1),(22,'18','mitre 1 3 x database changes','SQL','V18__mitre_1_3_x_database_changes.sql',449297336,'iam','2026-11-23 14:40:49',820,1),(23,'19','aup tables','SQL','V19__aup_tables.sql',567653912,'iam','2026-11-23 14:40:50',550,1),(24,'20','group membership request','SQL','V20__group_membership_request.sql',-924931434,'iam','2026-11-23 14:40:50',534,1),(25,'21',' device code default expiration','SQL','V21___device_code_default_expiration.sql',965164897,'iam','2026-11-23 14:40:50',1,1),(26,'22','add indexes for search queries','SQL','V22__add_indexes_for_search_queries.sql',-748445998,'iam','2026-11-23 14:40:50',350,1),(27,'23',' CreateGroupManagerAuthorities','JDBC','db.migration.mysql.V23___CreateGroupManagerAuthorities',NULL,'iam','2026-11-23 14:40:50',2,1),(28,'24',' set timestamp default','SQL','V24___set_timestamp_default.sql',234306337,'iam','2026-11-23 14:40:51',23,1),(29,'30',' default group support','SQL','V30___default_group_support.sql',-636476445,'iam','2026-11-23 14:40:52',1720,1),(30,'31',' address table fixes','SQL','V31___address_table_fixes.sql',323916075,'iam','2026-11-23 14:40:53',305,1),(31,'32',' proxy storage','SQL','V32___proxy_storage.sql',851904690,'iam','2026-11-23 14:40:53',405,1),(32,'33',' proxy api scopes','SQL','V33___proxy_api_scopes.sql',-394160567,'iam','2026-11-23 14:40:53',1,1),(33,'34',' req request labels','SQL','V34___req_request_labels.sql',-1247430935,'iam','2026-11-23 14:40:53',367,1),(34,'34.2',' RemoveOrphanTokens','JDBC','db.migration.mysql.V34_2___RemoveOrphanTokens',NULL,'iam','2026-11-23 14:40:53',3,1),(35,'35',' scope match policies','SQL','V35___scope_match_policies.sql',773238492,'iam','2026-11-23 14:40:54',307,1),(36,'40',' aup updates','SQL','V40___aup_updates.sql',-1574961084,'iam','2026-11-23 14:40:54',206,1),(37,'50',' token exchange policy','SQL','V50___token_exchange_policy.sql',708363568,'iam','2026-11-23 14:40:54',393,1),(38,'51',' fix scope match policies','SQL','V51___fix_scope_match_policies.sql',1742199118,'iam','2026-11-23 14:40:55',1,1),(39,'52','add eduperson system scopes','SQL','V52__add_eduperson_system_scopes.sql',-669332083,'iam','2026-11-23 14:40:55',2,1),(40,'53',' add end time to iam acccount','SQL','V53___add_end_time_to_iam_acccount.sql',795128555,'iam','2026-11-23 14:40:55',156,1),(41,'60',' fix certificate subject length','SQL','V60___fix_certificate_subject_length.sql',437826198,'iam','2026-11-23 14:40:55',386,1),(42,'61',' add dates for group membership','SQL','V61___add_dates_for_group_membership.sql',-1216009527,'iam','2026-11-23 14:40:55',102,1),(43,'62',' add dates to ssh keys table','SQL','V62___add_dates_to_ssh_keys_table.sql',345904759,'iam','2026-11-23 14:40:56',320,1),(44,'70',' totp mfa','SQL','V70___totp_mfa.sql',358166160,'iam','2026-11-23 14:40:56',487,1),(45,'71',' add pre authenticated authority','SQL','V71___add_pre_authenticated_authority.sql',234328656,'iam','2026-11-23 14:40:56',0,1),(46,'80',' account clients','SQL','V80___account_clients.sql',-2130998179,'iam','2026-11-23 14:40:57',636,1),(47,'81','add eduperson assurance scope','SQL','V81__add_eduperson_assurance_scope.sql',1118450873,'iam','2026-11-23 14:40:57',0,1),(48,'81.2',' RemoveOrphanTokens','JDBC','db.migration.mysql.V81_2___RemoveOrphanTokens',NULL,'iam','2026-11-23 14:40:57',2,1),(49,'90','fix eduperson entitlement scope','SQL','V90__fix_eduperson_entitlement_scope.sql',-543114581,'iam','2026-11-23 14:40:57',0,1),(50,'91','update client name','SQL','V91__update_client_name.sql',-113175668,'iam','2026-11-23 14:40:57',1,1),(51,'92','add iam api scopes','SQL','V92__add_iam_api_scopes.sql',1959900565,'iam','2026-11-23 14:40:57',0,1),(52,'93','add at hash','SQL','V93__add_at_hash.sql',-881840384,'iam','2026-11-23 14:40:57',491,1),(53,'94','alter x509 table','SQL','V94__alter_x509_table.sql',1887482211,'iam','2026-11-23 14:40:58',461,1),(54,'95','remove client response type','SQL','V95__remove_client_response_type.sql',-658578857,'iam','2026-11-23 14:40:58',3,1),(55,'96','add foreign keys','SQL','V96__add_foreign_keys.sql',-969456599,'iam','2026-11-23 14:41:04',5903,1),(56,'97','delete unique subject dn','SQL','V97__delete_unique_subject_dn.sql',1120054453,'iam','2026-11-23 14:41:04',78,1),(57,'98','fix rat hash value','SQL','V98__fix_rat_hash_value.sql',228664475,'iam','2026-11-23 14:41:04',1,1),(58,'99','clear client logo URI','SQL','V99__clear_client_logo_URI.sql',906005557,'iam','2026-11-23 14:41:04',2,1),(59,'100','alter saved user auth info table','SQL','V100__alter_saved_user_auth_info_table.sql',133009300,'iam','2026-11-23 14:41:04',19,1),(60,'101','add refresh token value index','SQL','V101__add_refresh_token_value_index.sql',-869693560,'iam','2026-11-23 14:41:04',37,1),(61,'102','client last used','SQL','V102__client_last_used.sql',606358214,'iam','2026-11-23 14:41:04',243,1),(62,'103','add active and status changed on to client details','SQL','V103__add_active_and_status_changed_on_to_client_details.sql',-1930375181,'iam','2026-11-23 14:41:04',54,1),(63,'104','set default active client status','SQL','V104__set_default_active_client_status.sql',794926784,'iam','2026-11-23 14:41:04',38,1),(64,'105','add aup reminders','SQL','V105__add_aup_reminders.sql',-1667681670,'iam','2026-11-23 14:41:04',37,1),(65,'106','jdbc session','SQL','V106__jdbc_session.sql',-1334238716,'iam','2026-11-23 14:41:05',402,1),(66,'107',' add reader authority','SQL','V107___add_reader_authority.sql',119140213,'iam','2026-11-23 14:41:05',1,1),(67,'108','add service account','SQL','V108__add_service_account.sql',245303774,'iam','2026-11-23 14:41:05',58,1),(68,'109','add affiliation to iam user info','SQL','V109__add_affiliation_to_iam_user_info.sql',-110440750,'iam','2026-11-23 14:41:05',47,1),(69,'110','client relying party','SQL','V110__client_relying_party.sql',1322161101,'iam','2026-11-23 14:41:05',210,1),(70,'111','add missing aarc scopes','SQL','V111__add_missing_aarc_scopes.sql',1681661037,'iam','2026-11-23 14:41:05',1,1),(71,'112','deprecate aarc scopes','SQL','V112__deprecate_aarc_scopes.sql',-18667466,'iam','2026-11-23 14:41:05',0,1),(72,'113','add at revocation table','SQL','V113__add_at_revocation_table.sql',1261044942,'iam','2026-11-23 14:41:05',69,1),(73,'114','add upScopingEnabled attribute','SQL','V114__add_upScopingEnabled_attribute.sql',1303388324,'iam','2026-11-23 14:41:06',54,1),(74,'115','alter saved user auth info key','SQL','V115__alter_saved_user_auth_info_key.sql',511119902,'iam','2026-11-23 14:41:06',194,1),(75,'116','store mfa admin key','SQL','V116__store_mfa_admin_key.sql',799475481,'iam','2026-11-23 14:41:06',99,1),(76,'117','change at revocation table','SQL','V117__change_at_revocation_table.sql',-647890026,'iam','2026-11-23 14:41:06',550,1),(77,'118','add shedlock table','SQL','V118__add_shedlock_table.sql',1031404319,'iam','2026-11-23 14:41:07',89,1),(78,'119','change last used date','SQL','V119__change_last_used_date.sql',1376698623,'iam','2026-11-23 14:41:07',358,1),(79,'120','remove at rt fk','SQL','V120__remove_at_rt_fk.sql',1309513260,'iam','2026-11-23 14:41:07',290,1),(80,'121','extend info val column length','SQL','V121__extend_info_val_column_length.sql',-405191539,'iam','2026-11-23 14:41:07',19,1),(81,'122','iam federated client table','SQL','V122__iam_federated_client_table.sql',-897743342,'iam','2026-11-23 14:41:08',468,1),(82,'123.1','DropAccessTokenValueIndexAndChangeCharSet','SQL','V123_1__DropAccessTokenValueIndexAndChangeCharSet.sql',-1777521096,'iam','2026-11-23 14:41:08',92,1),(83,'123.2','ExtractAccessTokenPayload','JDBC','db.migration.mysql.V123_2__ExtractAccessTokenPayload',NULL,'iam','2026-11-23 14:41:08',1,1),(84,'124','RemoveDanglingDeviceCodes','JDBC','db.migration.mysql.V124__RemoveDanglingDeviceCodes',NULL,'iam','2026-11-23 14:41:08',2,1),(85,'125','HashClientSecret','JDBC','db.migration.mysql.V125__HashClientSecret',NULL,'iam','2026-11-23 14:41:08',0,1),(86,'126','login lockout','SQL','V126__login_lockout.sql',1210744423,'iam','2026-11-23 14:41:08',239,1),(87,'127','delete implicit grant type and response types','SQL','V127__delete_implicit_grant_type_and_response_types.sql',-1831605413,'iam','2026-11-23 14:41:08',1,1),(88,'128','remove client credentials from public clients','SQL','V128__remove_client_credentials_from_public_clients.sql',-1288475567,'iam','2026-11-23 14:41:08',0,1),(89,'100000',' test data','SQL','V100000___test_data.sql',-1591180792,'iam','2026-11-23 14:41:08',89,1),(90,'100000.1',' CreateGroupManagerAuthorities','JDBC','db.migration.test.V100000_1___CreateGroupManagerAuthorities',NULL,'iam','2026-11-23 14:41:08',6,1),(91,'100000.3',' RemoveOrphanTokens','JDBC','db.migration.test.V100000_3___RemoveOrphanTokens',NULL,'iam','2026-11-23 14:41:08',2,1),(92,'100000.4',' remove data after orphan tokens test','SQL','V100000_4___remove_data_after_orphan_tokens_test.sql',-1771356196,'iam','2026-11-23 14:41:08',4,1),(93,'100000.8','add groupmanager user','SQL','V100000_8__add_groupmanager_user.sql',-616261434,'iam','2026-11-23 14:41:08',2,1),(94,'1000000.9',' HashClientSecret','JDBC','db.migration.test.V1000000_9___HashClientSecret',NULL,'iam','2026-11-23 14:41:09',10,1);
/*!40000 ALTER TABLE `schema_version` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `shedlock`
--

DROP TABLE IF EXISTS `shedlock`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `shedlock` (
  `name` varchar(64) NOT NULL,
  `lock_until` timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `locked_at` timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `locked_by` varchar(255) NOT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shedlock`
--

LOCK TABLES `shedlock` WRITE;
/*!40000 ALTER TABLE `shedlock` DISABLE KEYS */;
/*!40000 ALTER TABLE `shedlock` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `system_scope`
--

DROP TABLE IF EXISTS `system_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `system_scope` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `scope` varchar(256) NOT NULL,
  `description` varchar(4096) DEFAULT NULL,
  `icon` varchar(256) DEFAULT NULL,
  `restricted` tinyint(1) NOT NULL DEFAULT '0',
  `default_scope` tinyint(1) NOT NULL DEFAULT '0',
  `structured` tinyint(1) NOT NULL DEFAULT '0',
  `structured_param_description` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `scope` (`scope`)
) ENGINE=InnoDB AUTO_INCREMENT=31 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `system_scope`
--

LOCK TABLES `system_scope` WRITE;
/*!40000 ALTER TABLE `system_scope` DISABLE KEYS */;
INSERT INTO `system_scope` VALUES (1,'openid','log in using your identity','user',0,1,0,NULL),(2,'profile','basic profile information','list-alt',0,1,0,NULL),(3,'email','email address','envelope',0,1,0,NULL),(4,'address','physical address','home',0,1,0,NULL),(5,'phone','telephone number','bell',0,1,0,NULL),(6,'offline_access','offline access','time',0,0,0,NULL),(7,'scim:read','read access to SCIM user and groups',NULL,1,0,1,'read access to IAM SCIM APIs'),(8,'scim:write','write access to SCIM user and groups',NULL,1,0,1,'write access to IAM SCIM APIs'),(9,'registration:read','Grants read access to registration requests',NULL,1,0,1,'read access to IAM registration APIs'),(10,'registration:write','Grants write access to registration requests',NULL,1,0,1,'write access to IAM registration APIs'),(11,'scim','Authorizes access to IAM SCIM APIs',NULL,1,0,1,NULL),(12,'registration','Authorizes access to IAM registration APIs',NULL,1,0,1,NULL),(13,'proxy:generate','Authorizes access to IAM Proxy APIs',NULL,1,0,1,NULL),(16,'eduperson_scoped_affiliation','Access to EduPerson scoped affiliation information',NULL,0,0,0,NULL),(17,'eduperson_entitlement','Access to EduPerson entitlements information (DEPRECATED)',NULL,0,0,0,NULL),(18,'ssh-keys','Authorizes access to SSH keys linked to IAM accounts via the IAM userinfo endpoint',NULL,1,0,1,NULL),(19,'eduperson_assurance','Access to EduPerson assurance information',NULL,0,0,0,NULL),(20,'entitlements','Access to entitlements information',NULL,0,0,0,NULL),(21,'iam:admin.read','Read access to IAM APIs',NULL,1,0,0,NULL),(22,'iam:admin.write','Write access to IAM APIs',NULL,1,0,0,NULL),(23,'aarc','Get all eduPerson schema info','address-card',0,0,0,NULL),(24,'voperson_external_affiliation','Access to the home organisations that the user is affiliated with.',NULL,0,0,0,NULL),(25,'storage.read:/','Grants read privilege to WLCG storage',NULL,1,0,1,'Path parametric scope'),(26,'storage.write:/','Grants write privilege to WLCG storage',NULL,1,0,1,'Path parametric scope'),(27,'storage.modify:/','Grants modify privilege to WLCG storage',NULL,1,0,1,'Path parametric scope'),(28,'storage.stage:/','Grants recall privilege to WLCG storage',NULL,1,0,1,'Path parametric scope'),(29,'storage.create:/','Grants creation privilege to WLCG storage',NULL,1,0,1,'Path parametric scope'),(30,'wlcg.groups','WLCG groups',NULL,0,0,1,'Group parametric scope');
/*!40000 ALTER TABLE `system_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `token_scope`
--

DROP TABLE IF EXISTS `token_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `token_scope` (
  `owner_id` bigint NOT NULL,
  `scope` varchar(2048) NOT NULL,
  KEY `ts_oi_idx` (`owner_id`),
  CONSTRAINT `FK_token_scope_owner_id` FOREIGN KEY (`owner_id`) REFERENCES `access_token` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `token_scope`
--

LOCK TABLES `token_scope` WRITE;
/*!40000 ALTER TABLE `token_scope` DISABLE KEYS */;
INSERT INTO `token_scope` VALUES (1,'storage.create:/'),(1,'phone'),(1,'openid'),(1,'offline_access'),(1,'profile'),(1,'storage.read:/'),(1,'iam:admin.read'),(1,'storage.stage:/'),(1,'iam:admin.write'),(1,'storage.modify:/'),(1,'email'),(2,'storage.create:/'),(2,'phone'),(2,'openid'),(2,'offline_access'),(2,'profile'),(2,'storage.read:/'),(2,'storage.stage:/'),(2,'storage.modify:/'),(2,'email');
/*!40000 ALTER TABLE `token_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_info`
--

DROP TABLE IF EXISTS `user_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_info` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `sub` varchar(256) DEFAULT NULL,
  `preferred_username` varchar(256) DEFAULT NULL,
  `name` varchar(256) DEFAULT NULL,
  `given_name` varchar(256) DEFAULT NULL,
  `family_name` varchar(256) DEFAULT NULL,
  `middle_name` varchar(256) DEFAULT NULL,
  `nickname` varchar(256) DEFAULT NULL,
  `profile` varchar(256) DEFAULT NULL,
  `picture` varchar(256) DEFAULT NULL,
  `website` varchar(256) DEFAULT NULL,
  `email` varchar(256) DEFAULT NULL,
  `email_verified` tinyint(1) DEFAULT NULL,
  `gender` varchar(256) DEFAULT NULL,
  `zone_info` varchar(256) DEFAULT NULL,
  `locale` varchar(256) DEFAULT NULL,
  `phone_number` varchar(256) DEFAULT NULL,
  `phone_number_verified` tinyint(1) DEFAULT NULL,
  `address_id` varchar(256) DEFAULT NULL,
  `updated_time` varchar(256) DEFAULT NULL,
  `birthdate` varchar(256) DEFAULT NULL,
  `src` varchar(4096) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_info`
--

LOCK TABLES `user_info` WRITE;
/*!40000 ALTER TABLE `user_info` DISABLE KEYS */;
/*!40000 ALTER TABLE `user_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `whitelisted_site`
--

DROP TABLE IF EXISTS `whitelisted_site`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `whitelisted_site` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `creator_user_id` varchar(256) DEFAULT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `whitelisted_site`
--

LOCK TABLES `whitelisted_site` WRITE;
/*!40000 ALTER TABLE `whitelisted_site` DISABLE KEYS */;
INSERT INTO `whitelisted_site` VALUES (1,'admin','whitelist-client');
/*!40000 ALTER TABLE `whitelisted_site` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `whitelisted_site_scope`
--

DROP TABLE IF EXISTS `whitelisted_site_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `whitelisted_site_scope` (
  `owner_id` bigint DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `whitelisted_site_scope`
--

LOCK TABLES `whitelisted_site_scope` WRITE;
/*!40000 ALTER TABLE `whitelisted_site_scope` DISABLE KEYS */;
INSERT INTO `whitelisted_site_scope` VALUES (1,'openid'),(1,'profile');
/*!40000 ALTER TABLE `whitelisted_site_scope` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-11-23 18:25:35
