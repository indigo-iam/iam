--
-- Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

-- MySQL dump 10.13  Distrib 5.7.36, for Linux (x86_64)
--
-- Host: host.docker.internal    Database: iam
-- ------------------------------------------------------
-- Server version	5.7.36

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `access_token`
--

DROP TABLE IF EXISTS `access_token`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `access_token` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `token_value` varchar(4096) DEFAULT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  `token_type` varchar(256) DEFAULT NULL,
  `refresh_token_id` bigint(20) DEFAULT NULL,
  `client_id` bigint(20) DEFAULT NULL,
  `auth_holder_id` bigint(20) DEFAULT NULL,
  `id_token_id` bigint(20) DEFAULT NULL,
  `approved_site_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token_value` (`token_value`(766)),
  KEY `at_tv_idx` (`token_value`(767)),
  KEY `at_exp_idx` (`expiration`),
  KEY `at_ahi_idx` (`auth_holder_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `access_token`
--

LOCK TABLES `access_token` WRITE;
/*!40000 ALTER TABLE `access_token` DISABLE KEYS */;
/*!40000 ALTER TABLE `access_token` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `access_token_permissions`
--

DROP TABLE IF EXISTS `access_token_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `access_token_permissions` (
  `access_token_id` bigint(20) NOT NULL,
  `permission_id` bigint(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `address` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `formatted` varchar(256) DEFAULT NULL,
  `street_address` varchar(256) DEFAULT NULL,
  `locality` varchar(256) DEFAULT NULL,
  `region` varchar(256) DEFAULT NULL,
  `postal_code` varchar(256) DEFAULT NULL,
  `country` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `approved_site` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` varchar(256) DEFAULT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  `creation_date` timestamp NULL DEFAULT NULL,
  `access_date` timestamp NULL DEFAULT NULL,
  `timeout_date` timestamp NULL DEFAULT NULL,
  `whitelisted_site_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `approved_site_scope` (
  `owner_id` bigint(20) DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authentication_holder` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_auth_id` bigint(20) DEFAULT NULL,
  `approved` tinyint(1) DEFAULT NULL,
  `redirect_uri` varchar(2048) DEFAULT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder`
--

LOCK TABLES `authentication_holder` WRITE;
/*!40000 ALTER TABLE `authentication_holder` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_authority`
--

DROP TABLE IF EXISTS `authentication_holder_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authentication_holder_authority` (
  `owner_id` bigint(20) DEFAULT NULL,
  `authority` varchar(256) DEFAULT NULL,
  KEY `aha_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authentication_holder_extension` (
  `owner_id` bigint(20) DEFAULT NULL,
  `extension` varchar(2048) DEFAULT NULL,
  `val` varchar(2048) DEFAULT NULL,
  KEY `ahe_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_extension`
--

LOCK TABLES `authentication_holder_extension` WRITE;
/*!40000 ALTER TABLE `authentication_holder_extension` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder_extension` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_request_parameter`
--

DROP TABLE IF EXISTS `authentication_holder_request_parameter`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authentication_holder_request_parameter` (
  `owner_id` bigint(20) DEFAULT NULL,
  `param` varchar(2048) DEFAULT NULL,
  `val` varchar(2048) DEFAULT NULL,
  KEY `ahrp_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_request_parameter`
--

LOCK TABLES `authentication_holder_request_parameter` WRITE;
/*!40000 ALTER TABLE `authentication_holder_request_parameter` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder_request_parameter` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_resource_id`
--

DROP TABLE IF EXISTS `authentication_holder_resource_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authentication_holder_resource_id` (
  `owner_id` bigint(20) DEFAULT NULL,
  `resource_id` varchar(2048) DEFAULT NULL,
  KEY `ahri_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authentication_holder_response_type` (
  `owner_id` bigint(20) DEFAULT NULL,
  `response_type` varchar(2048) DEFAULT NULL,
  KEY `ahrt_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_response_type`
--

LOCK TABLES `authentication_holder_response_type` WRITE;
/*!40000 ALTER TABLE `authentication_holder_response_type` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder_response_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authentication_holder_scope`
--

DROP TABLE IF EXISTS `authentication_holder_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authentication_holder_scope` (
  `owner_id` bigint(20) DEFAULT NULL,
  `scope` varchar(2048) DEFAULT NULL,
  KEY `ahs_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authentication_holder_scope`
--

LOCK TABLES `authentication_holder_scope` WRITE;
/*!40000 ALTER TABLE `authentication_holder_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `authentication_holder_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authorization_code`
--

DROP TABLE IF EXISTS `authorization_code`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authorization_code` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `code` varchar(256) DEFAULT NULL,
  `auth_holder_id` bigint(20) DEFAULT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ac_ahi_idx` (`auth_holder_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `blacklisted_site` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `uri` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `claim` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(256) DEFAULT NULL,
  `friendly_name` varchar(1024) DEFAULT NULL,
  `claim_type` varchar(1024) DEFAULT NULL,
  `claim_value` varchar(1024) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `claim_issuer` (
  `owner_id` bigint(20) NOT NULL,
  `issuer` varchar(1024) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `claim_to_permission_ticket` (
  `permission_ticket_id` bigint(20) NOT NULL,
  `claim_id` bigint(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `claim_to_policy` (
  `policy_id` bigint(20) NOT NULL,
  `claim_id` bigint(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `claim_token_format` (
  `owner_id` bigint(20) NOT NULL,
  `claim_token_format` varchar(1024) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_authority` (
  `owner_id` bigint(20) DEFAULT NULL,
  `authority` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_claims_redirect_uri` (
  `owner_id` bigint(20) DEFAULT NULL,
  `redirect_uri` varchar(2048) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_contact` (
  `owner_id` bigint(20) DEFAULT NULL,
  `contact` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_contact`
--

LOCK TABLES `client_contact` WRITE;
/*!40000 ALTER TABLE `client_contact` DISABLE KEYS */;
/*!40000 ALTER TABLE `client_contact` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_default_acr_value`
--

DROP TABLE IF EXISTS `client_default_acr_value`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_default_acr_value` (
  `owner_id` bigint(20) DEFAULT NULL,
  `default_acr_value` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_details` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `client_description` varchar(1024) DEFAULT NULL,
  `reuse_refresh_tokens` tinyint(1) NOT NULL DEFAULT '1',
  `dynamically_registered` tinyint(1) NOT NULL DEFAULT '0',
  `allow_introspection` tinyint(1) NOT NULL DEFAULT '0',
  `id_token_validity_seconds` bigint(20) NOT NULL DEFAULT '600',
  `client_id` varchar(256) DEFAULT NULL,
  `client_secret` text,
  `access_token_validity_seconds` bigint(20) DEFAULT NULL,
  `refresh_token_validity_seconds` bigint(20) DEFAULT NULL,
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
  `default_max_age` bigint(20) DEFAULT NULL,
  `require_auth_time` tinyint(1) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `initiate_login_uri` varchar(2048) DEFAULT NULL,
  `clear_access_tokens_on_refresh` tinyint(1) NOT NULL DEFAULT '1',
  `software_statement` text,
  `code_challenge_method` varchar(256) DEFAULT NULL,
  `software_id` text,
  `software_version` text,
  `device_code_validity_seconds` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `client_id` (`client_id`),
  KEY `cd_ci_idx` (`client_id`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_details`
--

LOCK TABLES `client_details` WRITE;
/*!40000 ALTER TABLE `client_details` DISABLE KEYS */;
INSERT INTO `client_details` VALUES (1,NULL,1,0,1,600,'client','secret',3600,NULL,NULL,'Test Client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(2,NULL,1,0,1,0,'tasks-app','secret',0,NULL,NULL,'Tasks App','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(3,NULL,1,0,1,600,'post-client','secret',3600,NULL,NULL,'Post client','SECRET_POST',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(4,NULL,1,0,1,600,'client-cred','secret',3600,NULL,NULL,'Client credentials','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(5,NULL,1,0,1,600,'password-grant','secret',3600,NULL,NULL,'Password grant client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(6,NULL,1,0,1,600,'scim-client-ro','secret',3600,NULL,NULL,'SCIM client (read-only)','SECRET_POST',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(7,NULL,1,0,1,600,'scim-client-rw','secret',3600,NULL,NULL,'SCIM client (read-write)','SECRET_POST',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(8,NULL,1,0,1,600,'token-exchange-actor','secret',3600,NULL,NULL,'Token Exchange grant client actor','SECRET_POST',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(9,NULL,1,0,1,600,'token-exchange-subject','secret',3600,NULL,NULL,'Token Exchange grant client subject','SECRET_POST',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(10,NULL,1,0,1,600,'registration-client','secret',3600,NULL,NULL,'Registration service test client','SECRET_POST',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(11,NULL,1,0,1,600,'token-lookup-client','secret',3600,NULL,NULL,'Token lookup client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL),(12,NULL,1,0,1,600,'device-code-client','secret',3600,NULL,NULL,'Device code client','SECRET_BASIC',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,600),(13,NULL,1,0,0,600,'implicit-flow-client',NULL,3600,NULL,NULL,'Implicit Flow client',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,600),(14,NULL,1,0,0,600,'public-dc-client',NULL,3600,NULL,NULL,'Public Device Code client',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,600);
/*!40000 ALTER TABLE `client_details` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_grant_type`
--

DROP TABLE IF EXISTS `client_grant_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_grant_type` (
  `owner_id` bigint(20) DEFAULT NULL,
  `grant_type` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_grant_type`
--

LOCK TABLES `client_grant_type` WRITE;
/*!40000 ALTER TABLE `client_grant_type` DISABLE KEYS */;
INSERT INTO `client_grant_type` VALUES (1,'authorization_code'),(1,'urn:ietf:params:oauth:grant_type:redelegate'),(1,'implicit'),(1,'refresh_token'),(3,'authorization_code'),(3,'client_credentials'),(4,'password'),(4,'client_credentials'),(5,'password'),(5,'refresh_token'),(6,'client_credentials'),(7,'client_credentials'),(8,'urn:ietf:params:oauth:grant-type:token-exchange'),(8,'client_credentials'),(8,'password'),(8,'refresh_token'),(9,'password'),(9,'refresh_token'),(9,'client_credentials'),(10,'client_credentials'),(10,'refresh_token'),(11,'authorization_code'),(11,'refresh_token'),(11,'client_credentials'),(11,'urn:ietf:params:oauth:grant-type:token-exchange'),(12,'refresh_token'),(12,'urn:ietf:params:oauth:grant-type:device_code'),(13,'implicit'),(14,'urn:ietf:params:oauth:grant-type:device_code');
/*!40000 ALTER TABLE `client_grant_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_post_logout_redirect_uri`
--

DROP TABLE IF EXISTS `client_post_logout_redirect_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_post_logout_redirect_uri` (
  `owner_id` bigint(20) DEFAULT NULL,
  `post_logout_redirect_uri` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_redirect_uri` (
  `owner_id` bigint(20) DEFAULT NULL,
  `redirect_uri` varchar(2048) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_redirect_uri`
--

LOCK TABLES `client_redirect_uri` WRITE;
/*!40000 ALTER TABLE `client_redirect_uri` DISABLE KEYS */;
INSERT INTO `client_redirect_uri` VALUES (1,'http://localhost:9090/iam-test-client/openid_connect_login'),(1,'https://iam.local.io/iam-test-client/openid_connect_login'),(3,'http://localhost:4000/callback'),(4,'http://localhost:5000/callback'),(11,'http://localhost:1234/callback'),(13,'http://localhost:9876/implicit');
/*!40000 ALTER TABLE `client_redirect_uri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `client_request_uri`
--

DROP TABLE IF EXISTS `client_request_uri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_request_uri` (
  `owner_id` bigint(20) DEFAULT NULL,
  `request_uri` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_resource` (
  `owner_id` bigint(20) DEFAULT NULL,
  `resource_id` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_response_type` (
  `owner_id` bigint(20) DEFAULT NULL,
  `response_type` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `client_scope` (
  `owner_id` bigint(20) DEFAULT NULL,
  `scope` varchar(2048) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `client_scope`
--

LOCK TABLES `client_scope` WRITE;
/*!40000 ALTER TABLE `client_scope` DISABLE KEYS */;
INSERT INTO `client_scope` VALUES (1,'openid'),(1,'profile'),(1,'email'),(1,'address'),(1,'phone'),(1,'offline_access'),(1,'read-tasks'),(1,'write-tasks'),(1,'read:/'),(1,'write:/'),(1,'attr'),(2,'openid'),(2,'profile'),(2,'read-tasks'),(2,'write-tasks'),(3,'openid'),(3,'profile'),(3,'read-tasks'),(3,'write-tasks'),(4,'openid'),(4,'profile'),(4,'read-tasks'),(4,'write-tasks'),(4,'offline_access'),(4,'storage.read:/'),(4,'storage.write:/'),(4,'wlcg.groups'),(5,'openid'),(5,'profile'),(5,'email'),(5,'address'),(5,'phone'),(5,'offline_access'),(5,'scim:read'),(5,'scim:write'),(5,'proxy:generate'),(5,'wlcg.groups'),(5,'storage.read:/'),(5,'storage.modify:/'),(5,'storage.create:/'),(5,'attr'),(6,'openid'),(6,'profile'),(6,'email'),(6,'address'),(6,'phone'),(6,'offline_access'),(6,'scim:read'),(7,'openid'),(7,'profile'),(7,'email'),(7,'address'),(7,'phone'),(7,'offline_access'),(7,'scim:read'),(7,'scim:write'),(8,'openid'),(8,'profile'),(8,'email'),(8,'address'),(8,'phone'),(8,'offline_access'),(8,'read-tasks'),(8,'storage.read:/'),(8,'storage.write:/'),(9,'openid'),(9,'profile'),(9,'offline_access'),(9,'storage.read:/'),(9,'storage.write:/'),(10,'openid'),(10,'profile'),(10,'registration:read'),(10,'registration:write'),(10,'scim:write'),(10,'scim:read'),(11,'openid'),(11,'profile'),(11,'email'),(11,'address'),(11,'phone'),(11,'offline_access'),(11,'read-tasks'),(11,'write-tasks'),(12,'openid'),(12,'profile'),(12,'email'),(12,'address'),(12,'phone'),(12,'offline_access'),(13,'openid'),(13,'profile'),(13,'email'),(13,'address'),(13,'phone'),(14,'profile'),(14,'email'),(14,'address'),(14,'phone'),(5,'eduperson_scoped_affiliation'),(5,'eduperson_entitlement');
/*!40000 ALTER TABLE `client_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `device_code`
--

DROP TABLE IF EXISTS `device_code`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `device_code` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `device_code` varchar(1024) DEFAULT NULL,
  `user_code` varchar(1024) DEFAULT NULL,
  `expiration` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `client_id` varchar(256) DEFAULT NULL,
  `approved` tinyint(1) DEFAULT NULL,
  `auth_holder_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `device_code_request_parameter` (
  `owner_id` bigint(20) DEFAULT NULL,
  `param` varchar(2048) DEFAULT NULL,
  `val` varchar(2048) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `device_code_scope` (
  `owner_id` bigint(20) NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_account` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `active` tinyint(1) NOT NULL DEFAULT '0',
  `CREATIONTIME` datetime NOT NULL,
  `LASTUPDATETIME` datetime NOT NULL,
  `PASSWORD` varchar(128) DEFAULT NULL,
  `USERNAME` varchar(128) NOT NULL,
  `UUID` varchar(36) NOT NULL,
  `user_info_id` bigint(20) DEFAULT NULL,
  `confirmation_key` varchar(36) DEFAULT NULL,
  `reset_key` varchar(36) DEFAULT NULL,
  `provisioned` tinyint(1) NOT NULL DEFAULT '0',
  `last_login_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `USERNAME` (`USERNAME`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_account_user_info_id` (`user_info_id`),
  KEY `ia_ct_idx` (`CREATIONTIME`),
  KEY `ia_lut_idx` (`LASTUPDATETIME`),
  KEY `ia_llt_idx` (`last_login_time`),
  KEY `ia_et_idx` (`end_time`),
  CONSTRAINT `FK_iam_account_user_info_id` FOREIGN KEY (`user_info_id`) REFERENCES `iam_user_info` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=348 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account`
--

LOCK TABLES `iam_account` WRITE;
/*!40000 ALTER TABLE `iam_account` DISABLE KEYS */;
INSERT INTO `iam_account` VALUES (1,1,'2021-12-04 17:05:40','2021-12-04 17:05:40','$2a$10$FLeZ0UiM5uNM2EyHkXHS2O9yTdb6KNiKN5aAwABBG.1rA4lfOYHE2','admin','73f16d93-2441-4a50-88ff-85360d78c6b5',1,NULL,NULL,0,NULL,NULL),(2,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test','80e5fb8d-b7c8-451a-89ba-346ae278a66f',2,NULL,NULL,0,NULL,NULL),(3,1,'2021-12-04 17:05:40','2021-12-04 17:05:40','$2a$10$spRIKbju9x85wDxN.chBYOOh7rAj78Yhu0O5hq26nejgcikklHMXu','dup_email_0','bffc67b7-47fe-410c-a6a0-cf00173a8fbb',3,NULL,NULL,0,NULL,NULL),(4,1,'2021-12-04 17:05:40','2021-12-04 17:05:40','$2a$10$BzIUbKIaUlCf.YIEcOqZQ.MZ1jWJwJAOSTp1Ac9mO5Si0.dPqaEq.','dup_email_1','0a6fa72a-fb75-4a6c-9734-bfe673df70b3',4,NULL,NULL,0,NULL,NULL),(5,1,'2021-12-04 17:05:40','2021-12-04 17:05:40','$2a$10$Bc.21MLJDhvc.UIypbKha.AtRDLiRYZjl1LfMs4FK0MIo8wN4KgdS','dup_email_2','d836e5ec-246c-456c-8476-923ee2f831c8',5,NULL,NULL,0,NULL,NULL),(100,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_100','f2ce8cb2-a1db-4884-9ef0-d8842cc02b4a',100,NULL,NULL,0,NULL,NULL),(101,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_101','1a78b3b8-22d2-4746-9269-df55aceb036f',101,NULL,NULL,0,NULL,NULL),(102,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_102','a07d60c6-7ffa-475f-98e4-f9f648aa278b',102,NULL,NULL,0,NULL,NULL),(103,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_103','56e1b885-ea25-4ffc-ba17-fcde2b097d02',103,NULL,NULL,0,NULL,NULL),(104,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_104','67d2794d-c7fb-406e-9bc1-b66f43cbe60f',104,NULL,NULL,0,NULL,NULL),(105,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_105','d11e04f7-f369-4de6-9375-394f7d886ac7',105,NULL,NULL,0,NULL,NULL),(106,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_106','bbc76b76-9f9e-443b-8c63-cd775c50c6f3',106,NULL,NULL,0,NULL,NULL),(107,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_107','b15c850c-e6e0-4afb-a02d-374653bb102e',107,NULL,NULL,0,NULL,NULL),(108,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_108','afada6e8-d50d-47f6-912e-d6261605c771',108,NULL,NULL,0,NULL,NULL),(109,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_109','fa3b4c97-4787-4b49-a32c-5b4c74d5a7c8',109,NULL,NULL,0,NULL,NULL),(110,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_110','33165df6-4d49-4728-883c-3fd42720d46b',110,NULL,NULL,0,NULL,NULL),(111,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_111','15fb8d3a-003d-4ef9-8349-867d81d4ae9c',111,NULL,NULL,0,NULL,NULL),(112,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_112','7a4dda33-c2e5-4304-998a-3fa4df481123',112,NULL,NULL,0,NULL,NULL),(113,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_113','7013f989-0a95-43b5-8637-2e2360a73bb3',113,NULL,NULL,0,NULL,NULL),(114,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_114','12caabc8-4766-4028-98ff-f4d7f288a5f0',114,NULL,NULL,0,NULL,NULL),(115,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_115','f463ad2b-5814-4877-bb62-f954c67a8044',115,NULL,NULL,0,NULL,NULL),(116,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_116','28c656c4-5489-4654-a257-0806c6bab905',116,NULL,NULL,0,NULL,NULL),(117,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_117','11be5a72-9416-45fc-a0a7-f3e23c54bfda',117,NULL,NULL,0,NULL,NULL),(118,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_118','3cea2c01-786e-41a3-8fdf-4229cc4e3742',118,NULL,NULL,0,NULL,NULL),(119,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_119','e0247677-4542-4df3-8d75-8efa11e70911',119,NULL,NULL,0,NULL,NULL),(120,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_120','d905a115-d726-4e11-ba1f-b8482177bb05',120,NULL,NULL,0,NULL,NULL),(121,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_121','3479afd1-584c-4479-b6e2-25f6cef2f842',121,NULL,NULL,0,NULL,NULL),(122,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_122','8d4f467d-cb68-4feb-b898-71e4487e6820',122,NULL,NULL,0,NULL,NULL),(123,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_123','0ddee1c2-1426-4b83-b520-e20bdd8ef9b3',123,NULL,NULL,0,NULL,NULL),(124,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_124','b8b638be-6e09-4dbe-bcc0-776c2403e8c7',124,NULL,NULL,0,NULL,NULL),(125,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_125','1dc3108a-b5c0-4e5b-accd-925054075bc4',125,NULL,NULL,0,NULL,NULL),(126,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_126','5eed3374-c131-4513-84b7-dd0ff965da35',126,NULL,NULL,0,NULL,NULL),(127,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_127','2d0b4c36-0301-49f6-a20b-23b6ca48cee2',127,NULL,NULL,0,NULL,NULL),(128,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_128','db46065a-ba62-423d-9397-7bc6fab371a5',128,NULL,NULL,0,NULL,NULL),(129,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_129','d9dbaabf-c51a-45e5-aee1-25134ba283ac',129,NULL,NULL,0,NULL,NULL),(130,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_130','5678f40a-f361-464c-aa71-ffb48d163aaa',130,NULL,NULL,0,NULL,NULL),(131,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_131','209ae3b9-e266-4e57-a639-db29f61a7594',131,NULL,NULL,0,NULL,NULL),(132,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_132','f3fac505-d5c9-4d9c-83af-3976f357f19c',132,NULL,NULL,0,NULL,NULL),(133,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_133','13bfd34b-1dda-452e-bd9a-284aabccf07d',133,NULL,NULL,0,NULL,NULL),(134,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_134','15ccd152-1537-48d4-a55a-fd6565e5d86f',134,NULL,NULL,0,NULL,NULL),(135,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_135','6b2f4fc1-3e98-4f64-8fb4-517d2d4b3fa3',135,NULL,NULL,0,NULL,NULL),(136,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_136','398081ee-9c3c-4e5d-802c-90a4579030d4',136,NULL,NULL,0,NULL,NULL),(137,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_137','89a32317-dd45-481d-91a4-080e30c1f29e',137,NULL,NULL,0,NULL,NULL),(138,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_138','6dc0aa56-011d-45b8-bf26-cb03e8b40ccf',138,NULL,NULL,0,NULL,NULL),(139,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_139','cd62277e-5acf-41af-acea-b4d208cba29e',139,NULL,NULL,0,NULL,NULL),(140,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_140','0ae29eac-64ee-45b4-a2e7-e58b34c7ff0e',140,NULL,NULL,0,NULL,NULL),(141,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_141','0f7fe907-fa84-429e-8057-02d809375ba3',141,NULL,NULL,0,NULL,NULL),(142,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_142','7aa4a733-d318-4392-b3d3-6618263f667d',142,NULL,NULL,0,NULL,NULL),(143,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_143','b1d9b1ac-e77c-4d55-a895-cf0788ed2174',143,NULL,NULL,0,NULL,NULL),(144,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_144','f975f1f7-ad05-4d66-9905-d44c13cbd08b',144,NULL,NULL,0,NULL,NULL),(145,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_145','857f6e6d-e415-4850-a82b-59d557864910',145,NULL,NULL,0,NULL,NULL),(146,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_146','4e1c059c-1d06-4997-8bfa-5bd09fdb4571',146,NULL,NULL,0,NULL,NULL),(147,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_147','f4a0bc7f-b279-4caf-b8d1-c86a3c106f62',147,NULL,NULL,0,NULL,NULL),(148,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_148','007bbb9d-55b1-4f5e-80a5-bbcb22073db4',148,NULL,NULL,0,NULL,NULL),(149,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_149','a1d22bbf-9afe-49da-b75d-b58f825db351',149,NULL,NULL,0,NULL,NULL),(150,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_150','8c2351d5-5460-4b2d-b1bb-7b086130090e',150,NULL,NULL,0,NULL,NULL),(151,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_151','e6651896-66f8-4f63-b44f-71710fdb947c',151,NULL,NULL,0,NULL,NULL),(152,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_152','caf04a3c-8f35-40a3-99b6-48ba6a05d8b8',152,NULL,NULL,0,NULL,NULL),(153,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_153','d501e485-a306-4c9d-9baf-cc75f2321cfd',153,NULL,NULL,0,NULL,NULL),(154,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_154','57466d38-cae8-48bf-ac67-2cfc0266b5b0',154,NULL,NULL,0,NULL,NULL),(155,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_155','4bd5f059-f014-4356-8083-9c1a77adb6fd',155,NULL,NULL,0,NULL,NULL),(156,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_156','69130f52-f251-46fd-99ee-d646938e5f3f',156,NULL,NULL,0,NULL,NULL),(157,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_157','dedfb4f0-a545-44b3-abba-dd77103db894',157,NULL,NULL,0,NULL,NULL),(158,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_158','b5d98a8b-3780-4ace-ace1-ac12829dc469',158,NULL,NULL,0,NULL,NULL),(159,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_159','17de2f08-37fe-469d-b7b1-0e9ea9c6d2d8',159,NULL,NULL,0,NULL,NULL),(160,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_160','313abc40-4c88-45df-89e7-bd7bbf97b0fd',160,NULL,NULL,0,NULL,NULL),(161,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_161','c5d7fc06-16fc-4711-be37-27bbf2c2c07c',161,NULL,NULL,0,NULL,NULL),(162,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_162','ca31bf4d-f5da-4fc4-ae36-fd3cc0d35d7f',162,NULL,NULL,0,NULL,NULL),(163,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_163','dc98bb8e-4b91-4915-86fb-476c9503a936',163,NULL,NULL,0,NULL,NULL),(164,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_164','79dd006c-0e4c-4a79-8600-ef8a0ae5bc04',164,NULL,NULL,0,NULL,NULL),(165,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_165','05cdc1f7-7787-43d6-80c6-588277fefb9b',165,NULL,NULL,0,NULL,NULL),(166,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_166','dcdeb139-71ab-44f5-a709-ab33fec49882',166,NULL,NULL,0,NULL,NULL),(167,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_167','35a98804-b05e-47b0-917b-d72a4d4a5240',167,NULL,NULL,0,NULL,NULL),(168,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_168','5e4d4351-82c7-438d-8f83-ee2b7ebe1fe3',168,NULL,NULL,0,NULL,NULL),(169,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_169','e1a205e2-f202-402d-8542-4cfc529ef514',169,NULL,NULL,0,NULL,NULL),(170,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_170','a2e6271e-5b30-42d1-a211-494b98832676',170,NULL,NULL,0,NULL,NULL),(171,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_171','68515954-75ea-4022-9581-4cb4d28c6d6d',171,NULL,NULL,0,NULL,NULL),(172,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_172','41663b84-06b5-4787-a49e-1f745ca1eab3',172,NULL,NULL,0,NULL,NULL),(173,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_173','b257f456-bdae-4c58-8519-756abbda462a',173,NULL,NULL,0,NULL,NULL),(174,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_174','d848b9cb-05e4-4dcf-b9b7-431d83c41810',174,NULL,NULL,0,NULL,NULL),(175,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_175','b6859250-dcca-47ef-b013-f609468d2389',175,NULL,NULL,0,NULL,NULL),(176,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_176','e18bc682-897b-4696-a5ef-eee37a52a3de',176,NULL,NULL,0,NULL,NULL),(177,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_177','6b00471d-f496-4335-8209-5a9e13d18b9e',177,NULL,NULL,0,NULL,NULL),(178,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_178','35664644-7b32-4503-86f4-76adbb57762c',178,NULL,NULL,0,NULL,NULL),(179,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_179','7890415f-6563-4f25-bdf3-a5f45159a1b1',179,NULL,NULL,0,NULL,NULL),(180,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_180','a1edf880-e270-4dac-b69f-73e61c517397',180,NULL,NULL,0,NULL,NULL),(181,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_181','73520029-5901-4022-b9da-38ccd73fe799',181,NULL,NULL,0,NULL,NULL),(182,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_182','de5825a3-c585-45b3-88a1-7e5e80686826',182,NULL,NULL,0,NULL,NULL),(183,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_183','bb50b80a-f471-4f64-85fb-4e5051708a4a',183,NULL,NULL,0,NULL,NULL),(184,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_184','b7aa98b9-30da-468c-8566-06a5b804c4b9',184,NULL,NULL,0,NULL,NULL),(185,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_185','c230e253-f874-4365-8b0e-7ba5ebc1cc26',185,NULL,NULL,0,NULL,NULL),(186,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_186','7593dbbf-9286-460b-a234-32b560817f60',186,NULL,NULL,0,NULL,NULL),(187,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_187','ee1e2ce5-da23-4576-84e3-ad7cf4e0ce26',187,NULL,NULL,0,NULL,NULL),(188,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_188','bf1cc1be-f405-4282-b7be-9a4578670046',188,NULL,NULL,0,NULL,NULL),(189,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_189','e5ed670a-f944-40f0-8c10-d41c3350ead5',189,NULL,NULL,0,NULL,NULL),(190,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_190','8370db5c-e196-451a-9f5f-9b99c570cf46',190,NULL,NULL,0,NULL,NULL),(191,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_191','81498342-d247-4a60-80de-2c4cb4b1a84d',191,NULL,NULL,0,NULL,NULL),(192,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_192','213f1b3c-516e-4a6f-9785-d8c85d32f83e',192,NULL,NULL,0,NULL,NULL),(193,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_193','08ba27e6-b1b5-4d9e-a64a-6b5bc538bf43',193,NULL,NULL,0,NULL,NULL),(194,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_194','cf0cfa8e-377c-44a0-a6d1-a74ce1de08fb',194,NULL,NULL,0,NULL,NULL),(195,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_195','2ea66412-8dc2-4081-8d48-e3637ca82604',195,NULL,NULL,0,NULL,NULL),(196,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_196','4ed466eb-ee51-4433-9d0f-3a56216698a2',196,NULL,NULL,0,NULL,NULL),(197,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_197','cc03fc51-097d-43d6-bb6c-a0df72ec4838',197,NULL,NULL,0,NULL,NULL),(198,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_198','11844e66-8146-4263-aaa6-1fde7e5cfc58',198,NULL,NULL,0,NULL,NULL),(199,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_199','b5a954c6-69a9-473c-a4c4-83c4f7a88c1c',199,NULL,NULL,0,NULL,NULL),(200,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_200','167e359e-7833-4ce2-9f8b-f035cee39505',200,NULL,NULL,0,NULL,NULL),(201,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_201','5afb5430-a023-4a50-aa92-b134a0fb68b3',201,NULL,NULL,0,NULL,NULL),(202,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_202','de17b155-307c-4f9b-81f3-7f8b73d2526a',202,NULL,NULL,0,NULL,NULL),(203,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_203','c966145b-ac05-4a2c-874d-f7b585d1d03b',203,NULL,NULL,0,NULL,NULL),(204,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_204','1d88ea5a-ab5f-40b1-bd48-f18f86eef5d9',204,NULL,NULL,0,NULL,NULL),(205,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_205','6cb0be93-7829-4bfc-ba4a-4d2cdff45447',205,NULL,NULL,0,NULL,NULL),(206,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_206','e31a2ca7-fcaa-4b98-aac9-7e78f8605851',206,NULL,NULL,0,NULL,NULL),(207,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_207','f26899b7-64e0-4c16-9134-cef3774f1614',207,NULL,NULL,0,NULL,NULL),(208,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_208','606cf6ab-6b5e-45d1-83b8-e535b197d2f0',208,NULL,NULL,0,NULL,NULL),(209,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_209','617bfc4e-17b1-4ca7-b736-58a74c267747',209,NULL,NULL,0,NULL,NULL),(210,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_210','e5c26b7a-17bd-47ce-aac8-1430c57b8152',210,NULL,NULL,0,NULL,NULL),(211,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_211','7747bff5-b1e5-49b9-9a87-f93a5b790df0',211,NULL,NULL,0,NULL,NULL),(212,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_212','c6e5b631-1e91-4ecd-8358-214eec07a91d',212,NULL,NULL,0,NULL,NULL),(213,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_213','a874c7bd-97ac-4f48-bda5-7d3305d9067d',213,NULL,NULL,0,NULL,NULL),(214,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_214','c7938cc2-8032-424b-8f49-85558f95364b',214,NULL,NULL,0,NULL,NULL),(215,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_215','46017ce9-d4dd-4ddc-8b73-d596e23d25ad',215,NULL,NULL,0,NULL,NULL),(216,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_216','d5e66fd2-232e-476d-8de0-2bc1eb59630d',216,NULL,NULL,0,NULL,NULL),(217,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_217','097dc614-bc56-4f5f-a190-3ca1716a6400',217,NULL,NULL,0,NULL,NULL),(218,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_218','a3b97132-067f-4839-9b99-830a7fb659d4',218,NULL,NULL,0,NULL,NULL),(219,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_219','8d35557f-7451-4c54-bb17-9c3d204c48d3',219,NULL,NULL,0,NULL,NULL),(220,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_220','a6fba1ff-a5d7-4907-8cd4-1caa27cad85d',220,NULL,NULL,0,NULL,NULL),(221,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_221','427feb36-4401-4971-83de-f93672c028aa',221,NULL,NULL,0,NULL,NULL),(222,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_222','66541083-b1ab-4966-9f8b-8a1109fce0e0',222,NULL,NULL,0,NULL,NULL),(223,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_223','9939c37c-a9b9-43b7-9a4b-aacc470d47c4',223,NULL,NULL,0,NULL,NULL),(224,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_224','754379a0-bdc2-4a2d-9828-9480926b30ad',224,NULL,NULL,0,NULL,NULL),(225,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_225','18c870a1-9e2c-48fb-8a52-259e55e2052e',225,NULL,NULL,0,NULL,NULL),(226,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_226','02df9a97-b44c-4c46-ab3a-c11010d45e18',226,NULL,NULL,0,NULL,NULL),(227,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_227','20f609f7-c128-46b5-abeb-d16d46aab9ad',227,NULL,NULL,0,NULL,NULL),(228,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_228','75067ca5-872c-4149-85ad-f6685f14efc0',228,NULL,NULL,0,NULL,NULL),(229,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_229','b8639303-d15f-4c81-b9d2-2863f53737c3',229,NULL,NULL,0,NULL,NULL),(230,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_230','a0c4d9ea-7659-4009-ac7c-a3f089def76d',230,NULL,NULL,0,NULL,NULL),(231,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_231','d3605113-fb9a-4640-b6fe-9931594eba6c',231,NULL,NULL,0,NULL,NULL),(232,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_232','bf59d2cc-dd79-4ad6-9637-b04098768600',232,NULL,NULL,0,NULL,NULL),(233,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_233','304d5f24-274e-4fd6-aca4-97b761d1bd0c',233,NULL,NULL,0,NULL,NULL),(234,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_234','0d9491c3-c28b-4c11-8e28-14d93e612e35',234,NULL,NULL,0,NULL,NULL),(235,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_235','f73a809f-78a6-4214-8060-d6037fe391aa',235,NULL,NULL,0,NULL,NULL),(236,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_236','11cc494a-86a4-44d2-b5fd-06438f95d6a4',236,NULL,NULL,0,NULL,NULL),(237,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_237','55b2e8cc-aaa4-4a8b-8a83-f732188cfab2',237,NULL,NULL,0,NULL,NULL),(238,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_238','ebe14f0a-7bf7-4614-83c8-1e2da963139a',238,NULL,NULL,0,NULL,NULL),(239,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_239','3e83b092-95a1-4ee4-ac1f-e9df2f3954ad',239,NULL,NULL,0,NULL,NULL),(240,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_240','7304efcc-7974-453e-b2db-fdcc848f8a24',240,NULL,NULL,0,NULL,NULL),(241,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_241','6b0b51e8-f058-42a6-a9ed-3b6ebde935d8',241,NULL,NULL,0,NULL,NULL),(242,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_242','c10f6de1-a64d-4f8f-bd0a-47bcd72ab8f7',242,NULL,NULL,0,NULL,NULL),(243,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_243','5537408c-41c6-4ee5-8f59-ca70fcdbd0ae',243,NULL,NULL,0,NULL,NULL),(244,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_244','0a920520-e271-42a6-8dc1-89f090023c89',244,NULL,NULL,0,NULL,NULL),(245,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_245','a5120b27-cdd5-4209-b3da-bdf4b53db140',245,NULL,NULL,0,NULL,NULL),(246,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_246','cd0f900a-dab8-4a49-805d-97e57cb5ad4c',246,NULL,NULL,0,NULL,NULL),(247,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_247','53b8b68c-0a11-411a-9b4d-01d58c9c0ff0',247,NULL,NULL,0,NULL,NULL),(248,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_248','57114ddf-7bb8-4e68-952a-faa83bf276bf',248,NULL,NULL,0,NULL,NULL),(249,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_249','fa04c6fe-1bf0-489e-b0df-9fa4756bb90b',249,NULL,NULL,0,NULL,NULL),(250,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_250','5bf5b365-962e-4f6d-9576-94d5ac66cc3c',250,NULL,NULL,0,NULL,NULL),(251,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_251','eca96575-798c-4919-ba93-4f0eca487490',251,NULL,NULL,0,NULL,NULL),(252,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_252','d4e52ad1-ac1c-4f68-8d97-6858c8534f84',252,NULL,NULL,0,NULL,NULL),(253,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_253','74f88528-b57b-4482-a417-e7e8cf5ccd87',253,NULL,NULL,0,NULL,NULL),(254,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_254','f1b969bd-2e43-4981-80d1-baeba6afd456',254,NULL,NULL,0,NULL,NULL),(255,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_255','11f5bcd3-096b-4b0f-8f1b-fa9292e3f5f3',255,NULL,NULL,0,NULL,NULL),(256,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_256','b937e637-c00b-48de-8dd4-fae260cd9fb9',256,NULL,NULL,0,NULL,NULL),(257,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_257','49886ca5-c9a8-4c1f-9ef0-4784495e943c',257,NULL,NULL,0,NULL,NULL),(258,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_258','5cf6bbba-f2bf-4704-b288-36edb49a3c7a',258,NULL,NULL,0,NULL,NULL),(259,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_259','0a246675-78f2-47d3-a716-f9b85de0e885',259,NULL,NULL,0,NULL,NULL),(260,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_260','b1e2509b-e9e4-40f8-b5c3-4e230e675ca8',260,NULL,NULL,0,NULL,NULL),(261,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_261','c423ca4a-54b4-40f3-859d-d39f7d4cf266',261,NULL,NULL,0,NULL,NULL),(262,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_262','1452d005-8038-4092-ba0d-bd690dfdb2e2',262,NULL,NULL,0,NULL,NULL),(263,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_263','f39a1721-6aeb-4f1e-90be-f54684ece8f0',263,NULL,NULL,0,NULL,NULL),(264,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_264','ec2b02db-6eb2-4b9e-aa3b-ef53b6daf005',264,NULL,NULL,0,NULL,NULL),(265,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_265','a6809581-e7b7-4d70-bfdd-c1f302322ee3',265,NULL,NULL,0,NULL,NULL),(266,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_266','794e2ba9-518d-4494-8ef0-01669807e10a',266,NULL,NULL,0,NULL,NULL),(267,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_267','c258f48e-7f30-4c16-bd2d-6eed81529157',267,NULL,NULL,0,NULL,NULL),(268,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_268','b7501b84-3a14-44d7-97da-271c416cbd16',268,NULL,NULL,0,NULL,NULL),(269,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_269','88b529d5-7804-4c4d-9f35-aa7dd1df0a37',269,NULL,NULL,0,NULL,NULL),(270,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_270','0c1b65d3-dee3-4429-864f-115fbbc6a2f4',270,NULL,NULL,0,NULL,NULL),(271,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_271','01667b0f-b397-47c1-8cdb-adb3ea7cba06',271,NULL,NULL,0,NULL,NULL),(272,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_272','c8909fda-0453-4f74-a683-bd613fdc70c5',272,NULL,NULL,0,NULL,NULL),(273,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_273','796b8703-6f42-433f-b9e6-b115b4df25b0',273,NULL,NULL,0,NULL,NULL),(274,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_274','de8f11f6-7298-4633-ad38-cc94e03314fd',274,NULL,NULL,0,NULL,NULL),(275,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_275','e097f4e6-9c2d-4f35-912e-bd37f5cdec00',275,NULL,NULL,0,NULL,NULL),(276,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_276','3e0dab1e-c41f-4c0d-b2e3-d056ba6a3c60',276,NULL,NULL,0,NULL,NULL),(277,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_277','b24cb998-40b7-471c-b55a-48b58b98b2e5',277,NULL,NULL,0,NULL,NULL),(278,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_278','ab2113f4-56a2-4d1d-83a6-a54a763e371e',278,NULL,NULL,0,NULL,NULL),(279,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_279','2a2beb83-ccbf-413f-ade2-2fd2f79e5f49',279,NULL,NULL,0,NULL,NULL),(280,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_280','ac53405d-8813-4cf7-ac12-fad7629d5602',280,NULL,NULL,0,NULL,NULL),(281,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_281','b6c7b0e1-38b5-4e00-a22d-45c03d5fdeac',281,NULL,NULL,0,NULL,NULL),(282,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_282','8e41ff90-42f5-4736-89a6-24246917555c',282,NULL,NULL,0,NULL,NULL),(283,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_283','2b46023a-316f-41ae-955e-01185d67d7a5',283,NULL,NULL,0,NULL,NULL),(284,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_284','74c72c06-391e-4c72-92e7-92a5b75ac2da',284,NULL,NULL,0,NULL,NULL),(285,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_285','3e1246c2-96f9-4937-be0c-eb187822c3c7',285,NULL,NULL,0,NULL,NULL),(286,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_286','7f0e0193-b743-4394-b3e5-86e01813c094',286,NULL,NULL,0,NULL,NULL),(287,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_287','886cd06c-c30a-48df-b793-be4bfa2c1eb9',287,NULL,NULL,0,NULL,NULL),(288,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_288','cb7cf6cd-bd2e-4956-be86-5d5935417098',288,NULL,NULL,0,NULL,NULL),(289,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_289','d2e92f17-c26b-44dd-9c60-ca69b0f55b6d',289,NULL,NULL,0,NULL,NULL),(290,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_290','ea3a53a1-b451-4d7b-9b9f-2b6790de314d',290,NULL,NULL,0,NULL,NULL),(291,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_291','723f2b0d-3473-445c-a6f2-9c8bb12b6019',291,NULL,NULL,0,NULL,NULL),(292,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_292','8f04e723-bb30-4952-a8f5-214845e525dc',292,NULL,NULL,0,NULL,NULL),(293,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_293','56e1991e-47e1-4136-9bd0-cd94fa40b3c8',293,NULL,NULL,0,NULL,NULL),(294,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_294','b5ef5b82-483e-4331-ba84-78ece1f72602',294,NULL,NULL,0,NULL,NULL),(295,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_295','8238ae4e-5f13-42a3-9d6c-ea60f0ee64a1',295,NULL,NULL,0,NULL,NULL),(296,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_296','800a6a1d-1f63-4052-a14a-fcb56ab7e98b',296,NULL,NULL,0,NULL,NULL),(297,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_297','2eb884c0-8953-434d-898f-a162ffd44102',297,NULL,NULL,0,NULL,NULL),(298,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_298','06363941-bac6-4cc1-b56f-82d9d64d7c12',298,NULL,NULL,0,NULL,NULL),(299,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_299','d8468131-79a2-4003-bf0a-e034a3455af9',299,NULL,NULL,0,NULL,NULL),(300,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_300','e8e5f9d3-4473-46d9-b893-a195d5ccc6b4',300,NULL,NULL,0,NULL,NULL),(301,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_301','57db1144-49b7-4930-a214-9bba56c0eab6',301,NULL,NULL,0,NULL,NULL),(302,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_302','668a6ec5-142f-467d-891a-57fe10faf4bb',302,NULL,NULL,0,NULL,NULL),(303,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_303','9bcd9772-6c90-4c14-8ff4-16fa54744c87',303,NULL,NULL,0,NULL,NULL),(304,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_304','6c37ac4e-5213-4d60-8070-fadf3fa3ca38',304,NULL,NULL,0,NULL,NULL),(305,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_305','fb5d7ea0-249f-4a0e-97aa-caa015d148e4',305,NULL,NULL,0,NULL,NULL),(306,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_306','26035205-595c-433a-8aba-4e0d6ce103a3',306,NULL,NULL,0,NULL,NULL),(307,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_307','1e4a6346-9da9-417c-bfbf-1a3cded61e12',307,NULL,NULL,0,NULL,NULL),(308,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_308','3af98cba-0cd4-4ea1-bcdc-c4c91672f038',308,NULL,NULL,0,NULL,NULL),(309,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_309','a073f7ce-dfdc-424c-b4d0-bec7acaae445',309,NULL,NULL,0,NULL,NULL),(310,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_310','6524988e-5916-4410-a740-58d1e57d3f93',310,NULL,NULL,0,NULL,NULL),(311,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_311','58a190c4-789e-4c97-9fbb-245d3a58c8fe',311,NULL,NULL,0,NULL,NULL),(312,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_312','3244773f-b74b-461d-bf9a-916a05980c99',312,NULL,NULL,0,NULL,NULL),(313,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_313','aaed5fa8-6555-43d2-adf4-c672008f8c92',313,NULL,NULL,0,NULL,NULL),(314,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_314','f32415ac-f0fb-4815-bbef-27ba6115a1cc',314,NULL,NULL,0,NULL,NULL),(315,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_315','2030b697-b729-40c4-91b1-592e19fd4e73',315,NULL,NULL,0,NULL,NULL),(316,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_316','ee47b98e-ebd5-44ae-8c9a-cbec609415b0',316,NULL,NULL,0,NULL,NULL),(317,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_317','a47459c2-a709-4601-9151-cb57ae13bc8c',317,NULL,NULL,0,NULL,NULL),(318,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_318','5e274495-2c02-4f75-9ce2-c730e2686be9',318,NULL,NULL,0,NULL,NULL),(319,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_319','f5f04ca8-f693-4758-9aa6-9a3c55938937',319,NULL,NULL,0,NULL,NULL),(320,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_320','5f876faf-2ad7-41f3-906d-2edd9fd2907d',320,NULL,NULL,0,NULL,NULL),(321,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_321','3d0665c6-db74-4d48-91cc-ebe39bbae605',321,NULL,NULL,0,NULL,NULL),(322,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_322','86c19bce-cb25-47a4-8aba-29c8ad4fc87d',322,NULL,NULL,0,NULL,NULL),(323,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_323','efa06619-2301-4cb4-b9fa-6e9bddef94d7',323,NULL,NULL,0,NULL,NULL),(324,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_324','3cfc5976-aa7f-4281-8b43-6ea6eee1ac80',324,NULL,NULL,0,NULL,NULL),(325,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_325','19a56d56-1f57-45e6-9c2e-466a17d8c7ba',325,NULL,NULL,0,NULL,NULL),(326,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_326','026a45cf-cbeb-4ea9-8d20-21efbe206bad',326,NULL,NULL,0,NULL,NULL),(327,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_327','48312cae-f61d-4f87-9b20-a957d1e919ce',327,NULL,NULL,0,NULL,NULL),(328,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_328','e06abc58-f451-4e9e-ac4f-51d5e9d424a6',328,NULL,NULL,0,NULL,NULL),(329,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_329','10b58273-4b30-4caf-954c-a1873ca4d6b5',329,NULL,NULL,0,NULL,NULL),(330,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_330','008892b7-6479-4e68-adf2-39e7ac29e66e',330,NULL,NULL,0,NULL,NULL),(331,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_331','7f864422-153c-4681-8c9e-4e942dce9548',331,NULL,NULL,0,NULL,NULL),(332,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_332','67c5538e-0363-4650-a42e-ba25746b4239',332,NULL,NULL,0,NULL,NULL),(333,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_333','208210c1-1601-47ae-883f-cdb16e0f802b',333,NULL,NULL,0,NULL,NULL),(334,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_334','bb08395a-a0f0-490d-9d23-6f2f76b41514',334,NULL,NULL,0,NULL,NULL),(335,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_335','050c1a8e-256d-41ab-bd3a-3abe54d01b32',335,NULL,NULL,0,NULL,NULL),(336,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_336','cf016005-9207-4a2d-a8fe-91c278029a18',336,NULL,NULL,0,NULL,NULL),(337,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_337','950a5d40-e604-4f6c-82dd-2b60a578d9aa',337,NULL,NULL,0,NULL,NULL),(338,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_338','3e00662d-6917-4759-b9a9-be8eda02f63b',338,NULL,NULL,0,NULL,NULL),(339,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_339','bb339af3-2038-4f17-b489-46d4b7542cb6',339,NULL,NULL,0,NULL,NULL),(340,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_340','3927f6d5-5d90-4192-b84c-cebda90c0b0a',340,NULL,NULL,0,NULL,NULL),(341,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_341','e6b29f71-bb4a-420b-8442-1f7639109465',341,NULL,NULL,0,NULL,NULL),(342,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_342','ff7909b6-a90c-43c7-96fc-c375d439e373',342,NULL,NULL,0,NULL,NULL),(343,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_343','6f9902ca-7674-4f2f-b2e1-aeb3701bae14',343,NULL,NULL,0,NULL,NULL),(344,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_344','36d75eda-7573-474a-8aeb-f8555464154f',344,NULL,NULL,0,NULL,NULL),(345,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_345','d3c489ae-3f03-48fe-9248-927a8bb3297f',345,NULL,NULL,0,NULL,NULL),(346,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_346','18764a4e-8b01-478e-80b3-217cc37d49c7',346,NULL,NULL,0,NULL,NULL),(347,1,'2021-12-04 17:05:45','2021-12-04 17:05:45','$2a$10$UZeOZKD1.dj5oiTsZKD03OETA9FXCKGqBuuijhsxYygZpOPtWMUni','test_347','00075d1c-f486-41a0-98f8-06f0354b8416',347,NULL,NULL,0,NULL,NULL);
/*!40000 ALTER TABLE `iam_account` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_attrs`
--

DROP TABLE IF EXISTS `iam_account_attrs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_account_attrs` (
  `NAME` varchar(64) NOT NULL,
  `val` varchar(256) DEFAULT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  KEY `INDEX_iam_account_attrs_name` (`NAME`),
  KEY `INDEX_iam_account_attrs_name_val` (`NAME`,`val`),
  KEY `FK_iam_account_attrs_account_id` (`account_id`),
  CONSTRAINT `FK_iam_account_attrs_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_attrs`
--

LOCK TABLES `iam_account_attrs` WRITE;
/*!40000 ALTER TABLE `iam_account_attrs` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_account_attrs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_authority`
--

DROP TABLE IF EXISTS `iam_account_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_account_authority` (
  `account_id` bigint(20) NOT NULL,
  `authority_id` bigint(20) NOT NULL,
  PRIMARY KEY (`account_id`,`authority_id`),
  KEY `FK_iam_account_authority_authority_id` (`authority_id`),
  CONSTRAINT `FK_iam_account_authority_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_account_authority_authority_id` FOREIGN KEY (`authority_id`) REFERENCES `iam_authority` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_authority`
--

LOCK TABLES `iam_account_authority` WRITE;
/*!40000 ALTER TABLE `iam_account_authority` DISABLE KEYS */;
INSERT INTO `iam_account_authority` VALUES (1,1),(1,2),(2,2),(100,2),(101,2),(102,2),(103,2),(104,2),(105,2),(106,2),(107,2),(108,2),(109,2),(110,2),(111,2),(112,2),(113,2),(114,2),(115,2),(116,2),(117,2),(118,2),(119,2),(120,2),(121,2),(122,2),(123,2),(124,2),(125,2),(126,2),(127,2),(128,2),(129,2),(130,2),(131,2),(132,2),(133,2),(134,2),(135,2),(136,2),(137,2),(138,2),(139,2),(140,2),(141,2),(142,2),(143,2),(144,2),(145,2),(146,2),(147,2),(148,2),(149,2),(150,2),(151,2),(152,2),(153,2),(154,2),(155,2),(156,2),(157,2),(158,2),(159,2),(160,2),(161,2),(162,2),(163,2),(164,2),(165,2),(166,2),(167,2),(168,2),(169,2),(170,2),(171,2),(172,2),(173,2),(174,2),(175,2),(176,2),(177,2),(178,2),(179,2),(180,2),(181,2),(182,2),(183,2),(184,2),(185,2),(186,2),(187,2),(188,2),(189,2),(190,2),(191,2),(192,2),(193,2),(194,2),(195,2),(196,2),(197,2),(198,2),(199,2),(200,2),(201,2),(202,2),(203,2),(204,2),(205,2),(206,2),(207,2),(208,2),(209,2),(210,2),(211,2),(212,2),(213,2),(214,2),(215,2),(216,2),(217,2),(218,2),(219,2),(220,2),(221,2),(222,2),(223,2),(224,2),(225,2),(226,2),(227,2),(228,2),(229,2),(230,2),(231,2),(232,2),(233,2),(234,2),(235,2),(236,2),(237,2),(238,2),(239,2),(240,2),(241,2),(242,2),(243,2),(244,2),(245,2),(246,2),(247,2),(248,2),(249,2),(250,2),(251,2),(252,2),(253,2),(254,2),(255,2),(256,2),(257,2),(258,2),(259,2),(260,2),(261,2),(262,2),(263,2),(264,2),(265,2),(266,2),(267,2),(268,2),(269,2),(270,2),(271,2),(272,2),(273,2),(274,2),(275,2),(276,2),(277,2),(278,2),(279,2),(280,2),(281,2),(282,2),(283,2),(284,2),(285,2),(286,2),(287,2),(288,2),(289,2),(290,2),(291,2),(292,2),(293,2),(294,2),(295,2),(296,2),(297,2),(298,2),(299,2),(300,2),(301,2),(302,2),(303,2),(304,2),(305,2),(306,2),(307,2),(308,2),(309,2),(310,2),(311,2),(312,2),(313,2),(314,2),(315,2),(316,2),(317,2),(318,2),(319,2),(320,2),(321,2),(322,2),(323,2),(324,2),(325,2),(326,2),(327,2),(328,2),(329,2),(330,2),(331,2),(332,2),(333,2),(334,2),(335,2),(336,2),(337,2),(338,2),(339,2),(340,2),(341,2),(342,2),(343,2),(344,2),(345,2),(346,2),(347,2);
/*!40000 ALTER TABLE `iam_account_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_group`
--

DROP TABLE IF EXISTS `iam_account_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_account_group` (
  `account_id` bigint(20) NOT NULL,
  `group_id` bigint(20) NOT NULL,
  `creation_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  PRIMARY KEY (`account_id`,`group_id`),
  KEY `FK_iam_account_group_group_id` (`group_id`),
  CONSTRAINT `FK_iam_account_group_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_account_group_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_group`
--

LOCK TABLES `iam_account_group` WRITE;
/*!40000 ALTER TABLE `iam_account_group` DISABLE KEYS */;
INSERT INTO `iam_account_group` VALUES (2,1,NULL,NULL),(2,2,NULL,NULL),(100,1,NULL,NULL),(100,2,NULL,NULL),(101,1,NULL,NULL),(101,2,NULL,NULL),(102,1,NULL,NULL),(102,2,NULL,NULL),(103,1,NULL,NULL),(103,2,NULL,NULL),(104,1,NULL,NULL),(104,2,NULL,NULL),(105,1,NULL,NULL),(105,2,NULL,NULL),(106,1,NULL,NULL),(106,2,NULL,NULL),(107,1,NULL,NULL),(107,2,NULL,NULL),(108,1,NULL,NULL),(108,2,NULL,NULL),(109,1,NULL,NULL),(109,2,NULL,NULL),(110,1,NULL,NULL),(110,2,NULL,NULL),(111,1,NULL,NULL),(111,2,NULL,NULL),(112,1,NULL,NULL),(112,2,NULL,NULL),(113,1,NULL,NULL),(113,2,NULL,NULL),(114,1,NULL,NULL),(114,2,NULL,NULL),(115,1,NULL,NULL),(115,2,NULL,NULL),(116,1,NULL,NULL),(116,2,NULL,NULL),(117,1,NULL,NULL),(117,2,NULL,NULL),(118,1,NULL,NULL),(118,2,NULL,NULL),(119,1,NULL,NULL),(119,2,NULL,NULL),(120,1,NULL,NULL),(120,2,NULL,NULL),(121,1,NULL,NULL),(121,2,NULL,NULL),(122,1,NULL,NULL),(122,2,NULL,NULL),(123,1,NULL,NULL),(123,2,NULL,NULL),(124,1,NULL,NULL),(124,2,NULL,NULL),(125,1,NULL,NULL),(125,2,NULL,NULL),(126,1,NULL,NULL),(126,2,NULL,NULL),(127,1,NULL,NULL),(127,2,NULL,NULL),(128,1,NULL,NULL),(128,2,NULL,NULL),(129,1,NULL,NULL),(129,2,NULL,NULL),(130,1,NULL,NULL),(130,2,NULL,NULL),(131,1,NULL,NULL),(131,2,NULL,NULL),(132,1,NULL,NULL),(132,2,NULL,NULL),(133,1,NULL,NULL),(133,2,NULL,NULL),(134,1,NULL,NULL),(134,2,NULL,NULL),(135,1,NULL,NULL),(135,2,NULL,NULL),(136,1,NULL,NULL),(136,2,NULL,NULL),(137,1,NULL,NULL),(137,2,NULL,NULL),(138,1,NULL,NULL),(138,2,NULL,NULL),(139,1,NULL,NULL),(139,2,NULL,NULL),(140,1,NULL,NULL),(140,2,NULL,NULL),(141,1,NULL,NULL),(141,2,NULL,NULL),(142,1,NULL,NULL),(142,2,NULL,NULL),(143,1,NULL,NULL),(143,2,NULL,NULL),(144,1,NULL,NULL),(144,2,NULL,NULL),(145,1,NULL,NULL),(145,2,NULL,NULL),(146,1,NULL,NULL),(146,2,NULL,NULL),(147,1,NULL,NULL),(147,2,NULL,NULL),(148,1,NULL,NULL),(148,2,NULL,NULL),(149,1,NULL,NULL),(149,2,NULL,NULL),(150,1,NULL,NULL),(150,2,NULL,NULL),(151,1,NULL,NULL),(151,2,NULL,NULL),(152,1,NULL,NULL),(152,2,NULL,NULL),(153,1,NULL,NULL),(153,2,NULL,NULL),(154,1,NULL,NULL),(154,2,NULL,NULL),(155,1,NULL,NULL),(155,2,NULL,NULL),(156,1,NULL,NULL),(156,2,NULL,NULL),(157,1,NULL,NULL),(157,2,NULL,NULL),(158,1,NULL,NULL),(158,2,NULL,NULL),(159,1,NULL,NULL),(159,2,NULL,NULL),(160,1,NULL,NULL),(160,2,NULL,NULL),(161,1,NULL,NULL),(161,2,NULL,NULL),(162,1,NULL,NULL),(162,2,NULL,NULL),(163,1,NULL,NULL),(163,2,NULL,NULL),(164,1,NULL,NULL),(164,2,NULL,NULL),(165,1,NULL,NULL),(165,2,NULL,NULL),(166,1,NULL,NULL),(166,2,NULL,NULL),(167,1,NULL,NULL),(167,2,NULL,NULL),(168,1,NULL,NULL),(168,2,NULL,NULL),(169,1,NULL,NULL),(169,2,NULL,NULL),(170,1,NULL,NULL),(170,2,NULL,NULL),(171,1,NULL,NULL),(171,2,NULL,NULL),(172,1,NULL,NULL),(172,2,NULL,NULL),(173,1,NULL,NULL),(173,2,NULL,NULL),(174,1,NULL,NULL),(174,2,NULL,NULL),(175,1,NULL,NULL),(175,2,NULL,NULL),(176,1,NULL,NULL),(176,2,NULL,NULL),(177,1,NULL,NULL),(177,2,NULL,NULL),(178,1,NULL,NULL),(178,2,NULL,NULL),(179,1,NULL,NULL),(179,2,NULL,NULL),(180,1,NULL,NULL),(180,2,NULL,NULL),(181,1,NULL,NULL),(181,2,NULL,NULL),(182,1,NULL,NULL),(182,2,NULL,NULL),(183,1,NULL,NULL),(183,2,NULL,NULL),(184,1,NULL,NULL),(184,2,NULL,NULL),(185,1,NULL,NULL),(185,2,NULL,NULL),(186,1,NULL,NULL),(186,2,NULL,NULL),(187,1,NULL,NULL),(187,2,NULL,NULL),(188,1,NULL,NULL),(188,2,NULL,NULL),(189,1,NULL,NULL),(189,2,NULL,NULL),(190,1,NULL,NULL),(190,2,NULL,NULL),(191,1,NULL,NULL),(191,2,NULL,NULL),(192,1,NULL,NULL),(192,2,NULL,NULL),(193,1,NULL,NULL),(193,2,NULL,NULL),(194,1,NULL,NULL),(194,2,NULL,NULL),(195,1,NULL,NULL),(195,2,NULL,NULL),(196,1,NULL,NULL),(196,2,NULL,NULL),(197,1,NULL,NULL),(197,2,NULL,NULL),(198,1,NULL,NULL),(198,2,NULL,NULL),(199,1,NULL,NULL),(199,2,NULL,NULL),(200,1,NULL,NULL),(200,2,NULL,NULL),(201,1,NULL,NULL),(201,2,NULL,NULL),(202,1,NULL,NULL),(202,2,NULL,NULL),(203,1,NULL,NULL),(203,2,NULL,NULL),(204,1,NULL,NULL),(204,2,NULL,NULL),(205,1,NULL,NULL),(205,2,NULL,NULL),(206,1,NULL,NULL),(206,2,NULL,NULL),(207,1,NULL,NULL),(207,2,NULL,NULL),(208,1,NULL,NULL),(208,2,NULL,NULL),(209,1,NULL,NULL),(209,2,NULL,NULL),(210,1,NULL,NULL),(210,2,NULL,NULL),(211,1,NULL,NULL),(211,2,NULL,NULL),(212,1,NULL,NULL),(212,2,NULL,NULL),(213,1,NULL,NULL),(213,2,NULL,NULL),(214,1,NULL,NULL),(214,2,NULL,NULL),(215,1,NULL,NULL),(215,2,NULL,NULL),(216,1,NULL,NULL),(216,2,NULL,NULL),(217,1,NULL,NULL),(217,2,NULL,NULL),(218,1,NULL,NULL),(218,2,NULL,NULL),(219,1,NULL,NULL),(219,2,NULL,NULL),(220,1,NULL,NULL),(220,2,NULL,NULL),(221,1,NULL,NULL),(221,2,NULL,NULL),(222,1,NULL,NULL),(222,2,NULL,NULL),(223,1,NULL,NULL),(223,2,NULL,NULL),(224,1,NULL,NULL),(224,2,NULL,NULL),(225,1,NULL,NULL),(225,2,NULL,NULL),(226,1,NULL,NULL),(226,2,NULL,NULL),(227,1,NULL,NULL),(227,2,NULL,NULL),(228,1,NULL,NULL),(228,2,NULL,NULL),(229,1,NULL,NULL),(229,2,NULL,NULL),(230,1,NULL,NULL),(230,2,NULL,NULL),(231,1,NULL,NULL),(231,2,NULL,NULL),(232,1,NULL,NULL),(232,2,NULL,NULL),(233,1,NULL,NULL),(233,2,NULL,NULL),(234,1,NULL,NULL),(234,2,NULL,NULL),(235,1,NULL,NULL),(235,2,NULL,NULL),(236,1,NULL,NULL),(236,2,NULL,NULL),(237,1,NULL,NULL),(237,2,NULL,NULL),(238,1,NULL,NULL),(238,2,NULL,NULL),(239,1,NULL,NULL),(239,2,NULL,NULL),(240,1,NULL,NULL),(240,2,NULL,NULL),(241,1,NULL,NULL),(241,2,NULL,NULL),(242,1,NULL,NULL),(242,2,NULL,NULL),(243,1,NULL,NULL),(243,2,NULL,NULL),(244,1,NULL,NULL),(244,2,NULL,NULL),(245,1,NULL,NULL),(245,2,NULL,NULL),(246,1,NULL,NULL),(246,2,NULL,NULL),(247,1,NULL,NULL),(247,2,NULL,NULL),(248,1,NULL,NULL),(248,2,NULL,NULL),(249,1,NULL,NULL),(249,2,NULL,NULL),(250,1,NULL,NULL),(250,2,NULL,NULL),(251,1,NULL,NULL),(251,2,NULL,NULL),(252,1,NULL,NULL),(252,2,NULL,NULL),(253,1,NULL,NULL),(253,2,NULL,NULL),(254,1,NULL,NULL),(254,2,NULL,NULL),(255,1,NULL,NULL),(255,2,NULL,NULL),(256,1,NULL,NULL),(256,2,NULL,NULL),(257,1,NULL,NULL),(257,2,NULL,NULL),(258,1,NULL,NULL),(258,2,NULL,NULL),(259,1,NULL,NULL),(259,2,NULL,NULL),(260,1,NULL,NULL),(260,2,NULL,NULL),(261,1,NULL,NULL),(261,2,NULL,NULL),(262,1,NULL,NULL),(262,2,NULL,NULL),(263,1,NULL,NULL),(263,2,NULL,NULL),(264,1,NULL,NULL),(264,2,NULL,NULL),(265,1,NULL,NULL),(265,2,NULL,NULL),(266,1,NULL,NULL),(266,2,NULL,NULL),(267,1,NULL,NULL),(267,2,NULL,NULL),(268,1,NULL,NULL),(268,2,NULL,NULL),(269,1,NULL,NULL),(269,2,NULL,NULL),(270,1,NULL,NULL),(270,2,NULL,NULL),(271,1,NULL,NULL),(271,2,NULL,NULL),(272,1,NULL,NULL),(272,2,NULL,NULL),(273,1,NULL,NULL),(273,2,NULL,NULL),(274,1,NULL,NULL),(274,2,NULL,NULL),(275,1,NULL,NULL),(275,2,NULL,NULL),(276,1,NULL,NULL),(276,2,NULL,NULL),(277,1,NULL,NULL),(277,2,NULL,NULL),(278,1,NULL,NULL),(278,2,NULL,NULL),(279,1,NULL,NULL),(279,2,NULL,NULL),(280,1,NULL,NULL),(280,2,NULL,NULL),(281,1,NULL,NULL),(281,2,NULL,NULL),(282,1,NULL,NULL),(282,2,NULL,NULL),(283,1,NULL,NULL),(283,2,NULL,NULL),(284,1,NULL,NULL),(284,2,NULL,NULL),(285,1,NULL,NULL),(285,2,NULL,NULL),(286,1,NULL,NULL),(286,2,NULL,NULL),(287,1,NULL,NULL),(287,2,NULL,NULL),(288,1,NULL,NULL),(288,2,NULL,NULL),(289,1,NULL,NULL),(289,2,NULL,NULL),(290,1,NULL,NULL),(290,2,NULL,NULL),(291,1,NULL,NULL),(291,2,NULL,NULL),(292,1,NULL,NULL),(292,2,NULL,NULL),(293,1,NULL,NULL),(293,2,NULL,NULL),(294,1,NULL,NULL),(294,2,NULL,NULL),(295,1,NULL,NULL),(295,2,NULL,NULL),(296,1,NULL,NULL),(296,2,NULL,NULL),(297,1,NULL,NULL),(297,2,NULL,NULL),(298,1,NULL,NULL),(298,2,NULL,NULL),(299,1,NULL,NULL),(299,2,NULL,NULL),(300,1,NULL,NULL),(300,2,NULL,NULL),(301,1,NULL,NULL),(301,2,NULL,NULL),(302,1,NULL,NULL),(302,2,NULL,NULL),(303,1,NULL,NULL),(303,2,NULL,NULL),(304,1,NULL,NULL),(304,2,NULL,NULL),(305,1,NULL,NULL),(305,2,NULL,NULL),(306,1,NULL,NULL),(306,2,NULL,NULL),(307,1,NULL,NULL),(307,2,NULL,NULL),(308,1,NULL,NULL),(308,2,NULL,NULL),(309,1,NULL,NULL),(309,2,NULL,NULL),(310,1,NULL,NULL),(310,2,NULL,NULL),(311,1,NULL,NULL),(311,2,NULL,NULL),(312,1,NULL,NULL),(312,2,NULL,NULL),(313,1,NULL,NULL),(313,2,NULL,NULL),(314,1,NULL,NULL),(314,2,NULL,NULL),(315,1,NULL,NULL),(315,2,NULL,NULL),(316,1,NULL,NULL),(316,2,NULL,NULL),(317,1,NULL,NULL),(317,2,NULL,NULL),(318,1,NULL,NULL),(318,2,NULL,NULL),(319,1,NULL,NULL),(319,2,NULL,NULL),(320,1,NULL,NULL),(320,2,NULL,NULL),(321,1,NULL,NULL),(321,2,NULL,NULL),(322,1,NULL,NULL),(322,2,NULL,NULL),(323,1,NULL,NULL),(323,2,NULL,NULL),(324,1,NULL,NULL),(324,2,NULL,NULL),(325,1,NULL,NULL),(325,2,NULL,NULL),(326,1,NULL,NULL),(326,2,NULL,NULL),(327,1,NULL,NULL),(327,2,NULL,NULL),(328,1,NULL,NULL),(328,2,NULL,NULL),(329,1,NULL,NULL),(329,2,NULL,NULL),(330,1,NULL,NULL),(330,2,NULL,NULL),(331,1,NULL,NULL),(331,2,NULL,NULL),(332,1,NULL,NULL),(332,2,NULL,NULL),(333,1,NULL,NULL),(333,2,NULL,NULL),(334,1,NULL,NULL),(334,2,NULL,NULL),(335,1,NULL,NULL),(335,2,NULL,NULL),(336,1,NULL,NULL),(336,2,NULL,NULL),(337,1,NULL,NULL),(337,2,NULL,NULL),(338,1,NULL,NULL),(338,2,NULL,NULL),(339,1,NULL,NULL),(339,2,NULL,NULL),(340,1,NULL,NULL),(340,2,NULL,NULL),(341,1,NULL,NULL),(341,2,NULL,NULL),(342,1,NULL,NULL),(342,2,NULL,NULL),(343,1,NULL,NULL),(343,2,NULL,NULL),(344,1,NULL,NULL),(344,2,NULL,NULL),(345,1,NULL,NULL),(345,2,NULL,NULL),(346,1,NULL,NULL),(346,2,NULL,NULL),(347,1,NULL,NULL),(347,2,NULL,NULL);
/*!40000 ALTER TABLE `iam_account_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_account_labels`
--

DROP TABLE IF EXISTS `iam_account_labels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_account_labels` (
  `NAME` varchar(64) NOT NULL,
  `PREFIX` varchar(256) DEFAULT NULL,
  `val` varchar(64) DEFAULT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  KEY `INDEX_iam_account_labels_prefix_name_val` (`PREFIX`,`NAME`,`val`),
  KEY `INDEX_iam_account_labels_prefix_name` (`PREFIX`,`NAME`),
  KEY `FK_iam_account_labels_account_id` (`account_id`),
  CONSTRAINT `FK_iam_account_labels_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_account_labels`
--

LOCK TABLES `iam_account_labels` WRITE;
/*!40000 ALTER TABLE `iam_account_labels` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_account_labels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_address`
--

DROP TABLE IF EXISTS `iam_address`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_address` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `COUNTRY` varchar(2) DEFAULT NULL,
  `FORMATTED` varchar(128) DEFAULT NULL,
  `LOCALITY` varchar(128) DEFAULT NULL,
  `POSTALCODE` varchar(16) DEFAULT NULL,
  `REGION` varchar(128) DEFAULT NULL,
  `STREETADDRESS` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_aup` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `description` varchar(128) DEFAULT NULL,
  `last_update_time` datetime NOT NULL,
  `name` varchar(36) NOT NULL,
  `sig_validity_days` bigint(20) NOT NULL,
  `text` longtext,
  `url` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_aup_signature` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `signature_time` datetime NOT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  `aup_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UNQ_iam_aup_signature_0` (`aup_id`,`account_id`),
  KEY `FK_iam_aup_signature_account_id` (`account_id`),
  CONSTRAINT `FK_iam_aup_signature_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_aup_signature_aup_id` FOREIGN KEY (`aup_id`) REFERENCES `iam_aup` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_authority` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `auth` varchar(128) NOT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `auth` (`auth`)
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_authority`
--

LOCK TABLES `iam_authority` WRITE;
/*!40000 ALTER TABLE `iam_authority` DISABLE KEYS */;
INSERT INTO `iam_authority` VALUES (1,'ROLE_ADMIN'),(4,'ROLE_GM:6a384bcd-d4b3-4b7f-a2fe-7d897ada0dd1'),(5,'ROLE_GM:c617d586-54e6-411d-8e38-649677980001'),(6,'ROLE_GM:c617d586-54e6-411d-8e38-649677980002'),(7,'ROLE_GM:c617d586-54e6-411d-8e38-649677980003'),(8,'ROLE_GM:c617d586-54e6-411d-8e38-649677980004'),(9,'ROLE_GM:c617d586-54e6-411d-8e38-649677980005'),(10,'ROLE_GM:c617d586-54e6-411d-8e38-649677980006'),(11,'ROLE_GM:c617d586-54e6-411d-8e38-649677980007'),(12,'ROLE_GM:c617d586-54e6-411d-8e38-649677980008'),(13,'ROLE_GM:c617d586-54e6-411d-8e38-649677980009'),(14,'ROLE_GM:c617d586-54e6-411d-8e38-649677980010'),(15,'ROLE_GM:c617d586-54e6-411d-8e38-649677980011'),(16,'ROLE_GM:c617d586-54e6-411d-8e38-649677980012'),(17,'ROLE_GM:c617d586-54e6-411d-8e38-649677980013'),(18,'ROLE_GM:c617d586-54e6-411d-8e38-649677980014'),(19,'ROLE_GM:c617d586-54e6-411d-8e38-649677980015'),(20,'ROLE_GM:c617d586-54e6-411d-8e38-649677980016'),(21,'ROLE_GM:c617d586-54e6-411d-8e38-649677980017'),(22,'ROLE_GM:c617d586-54e6-411d-8e38-649677980018'),(23,'ROLE_GM:c617d586-54e6-411d-8e38-649677980019'),(24,'ROLE_GM:c617d586-54e6-411d-8e38-649677980020'),(3,'ROLE_GM:c617d586-54e6-411d-8e38-64967798fa8a'),(2,'ROLE_USER');
/*!40000 ALTER TABLE `iam_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_email_notification`
--

DROP TABLE IF EXISTS `iam_email_notification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_email_notification` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `UUID` varchar(36) NOT NULL,
  `NOTIFICATION_TYPE` varchar(128) NOT NULL,
  `SUBJECT` varchar(128) DEFAULT NULL,
  `BODY` text,
  `CREATION_TIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `DELIVERY_STATUS` varchar(128) DEFAULT NULL,
  `LAST_UPDATE` timestamp NULL DEFAULT NULL,
  `REQUEST_ID` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_email_notification_request_id` (`REQUEST_ID`),
  CONSTRAINT `FK_iam_email_notification_request_id` FOREIGN KEY (`REQUEST_ID`) REFERENCES `iam_reg_request` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_exchange_policy` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `description` varchar(512) DEFAULT NULL,
  `last_update_time` datetime NOT NULL,
  `rule` varchar(6) NOT NULL,
  `dest_m_param` varchar(256) DEFAULT NULL,
  `dest_m_type` varchar(8) NOT NULL,
  `origin_m_param` varchar(256) DEFAULT NULL,
  `origin_m_type` varchar(8) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_exchange_policy`
--

LOCK TABLES `iam_exchange_policy` WRITE;
/*!40000 ALTER TABLE `iam_exchange_policy` DISABLE KEYS */;
INSERT INTO `iam_exchange_policy` VALUES (1,'2021-12-04 17:05:44','Allow all exchanges','2021-12-04 17:05:44','PERMIT',NULL,'ANY',NULL,'ANY');
/*!40000 ALTER TABLE `iam_exchange_policy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_exchange_scope_policies`
--

DROP TABLE IF EXISTS `iam_exchange_scope_policies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_exchange_scope_policies` (
  `param` varchar(256) DEFAULT NULL,
  `rule` varchar(6) NOT NULL,
  `type` varchar(6) NOT NULL,
  `exchange_policy_id` bigint(20) DEFAULT NULL,
  KEY `FK_iam_exchange_scope_policies_exchange_policy_id` (`exchange_policy_id`),
  CONSTRAINT `FK_iam_exchange_scope_policies_exchange_policy_id` FOREIGN KEY (`exchange_policy_id`) REFERENCES `iam_exchange_policy` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_ext_authn` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `authentication_time` datetime NOT NULL,
  `expiration_time` datetime NOT NULL,
  `saved_authn_id` bigint(20) DEFAULT NULL,
  `type` varchar(32) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `saved_authn_id` (`saved_authn_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_ext_authn_attr` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `value` varchar(512) NOT NULL,
  `details_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FK_iam_ext_authn_attr_details_id` (`details_id`),
  CONSTRAINT `FK_iam_ext_authn_attr_details_id` FOREIGN KEY (`details_id`) REFERENCES `iam_ext_authn` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_ext_authn_attr`
--

LOCK TABLES `iam_ext_authn_attr` WRITE;
/*!40000 ALTER TABLE `iam_ext_authn_attr` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_ext_authn_attr` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group`
--

DROP TABLE IF EXISTS `iam_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_group` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `CREATIONTIME` datetime NOT NULL,
  `DESCRIPTION` varchar(512) DEFAULT NULL,
  `LASTUPDATETIME` datetime NOT NULL,
  `name` varchar(512) NOT NULL,
  `UUID` varchar(36) NOT NULL,
  `parent_group_id` bigint(20) DEFAULT NULL,
  `default_group` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `NAME` (`name`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_group_parent_id` (`parent_group_id`),
  CONSTRAINT `FK_iam_group_parent_id` FOREIGN KEY (`parent_group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=121 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_group`
--

LOCK TABLES `iam_group` WRITE;
/*!40000 ALTER TABLE `iam_group` DISABLE KEYS */;
INSERT INTO `iam_group` VALUES (1,'2021-12-04 17:05:45','The production group','2021-12-04 17:05:45','Production','c617d586-54e6-411d-8e38-64967798fa8a',NULL,0),(2,'2021-12-04 17:05:45','The analysis group','2021-12-04 17:05:45','Analysis','6a384bcd-d4b3-4b7f-a2fe-7d897ada0dd1',NULL,0),(101,'2021-12-04 17:05:45','Test group-001','2021-12-04 17:05:45','Test-001','c617d586-54e6-411d-8e38-649677980001',NULL,0),(102,'2021-12-04 17:05:45','Test group-002','2021-12-04 17:05:45','Test-002','c617d586-54e6-411d-8e38-649677980002',NULL,0),(103,'2021-12-04 17:05:45','Test group-003','2021-12-04 17:05:45','Test-003','c617d586-54e6-411d-8e38-649677980003',NULL,0),(104,'2021-12-04 17:05:45','Test group-004','2021-12-04 17:05:45','Test-004','c617d586-54e6-411d-8e38-649677980004',NULL,0),(105,'2021-12-04 17:05:45','Test group-005','2021-12-04 17:05:45','Test-005','c617d586-54e6-411d-8e38-649677980005',NULL,0),(106,'2021-12-04 17:05:45','Test group-006','2021-12-04 17:05:45','Test-006','c617d586-54e6-411d-8e38-649677980006',NULL,0),(107,'2021-12-04 17:05:45','Test group-007','2021-12-04 17:05:45','Test-007','c617d586-54e6-411d-8e38-649677980007',NULL,0),(108,'2021-12-04 17:05:45','Test group-008','2021-12-04 17:05:45','Test-008','c617d586-54e6-411d-8e38-649677980008',NULL,0),(109,'2021-12-04 17:05:45','Test group-009','2021-12-04 17:05:45','Test-009','c617d586-54e6-411d-8e38-649677980009',NULL,0),(110,'2021-12-04 17:05:45','Test group-010','2021-12-04 17:05:45','Test-010','c617d586-54e6-411d-8e38-649677980010',NULL,0),(111,'2021-12-04 17:05:45','Test group-011','2021-12-04 17:05:45','Test-011','c617d586-54e6-411d-8e38-649677980011',NULL,0),(112,'2021-12-04 17:05:45','Test group-012','2021-12-04 17:05:45','Test-012','c617d586-54e6-411d-8e38-649677980012',NULL,0),(113,'2021-12-04 17:05:45','Test group-013','2021-12-04 17:05:45','Test-013','c617d586-54e6-411d-8e38-649677980013',NULL,0),(114,'2021-12-04 17:05:45','Test group-014','2021-12-04 17:05:45','Test-014','c617d586-54e6-411d-8e38-649677980014',NULL,0),(115,'2021-12-04 17:05:45','Test group-015','2021-12-04 17:05:45','Test-015','c617d586-54e6-411d-8e38-649677980015',NULL,0),(116,'2021-12-04 17:05:45','Test group-016','2021-12-04 17:05:45','Test-016','c617d586-54e6-411d-8e38-649677980016',NULL,0),(117,'2021-12-04 17:05:45','Test group-017','2021-12-04 17:05:45','Test-017','c617d586-54e6-411d-8e38-649677980017',NULL,0),(118,'2021-12-04 17:05:45','Test group-018','2021-12-04 17:05:45','Test-018','c617d586-54e6-411d-8e38-649677980018',NULL,0),(119,'2021-12-04 17:05:45','Test group-019','2021-12-04 17:05:45','Test-019','c617d586-54e6-411d-8e38-649677980019',NULL,0),(120,'2021-12-04 17:05:45','Test group-020','2021-12-04 17:05:45','Test-020','c617d586-54e6-411d-8e38-649677980020',NULL,0);
/*!40000 ALTER TABLE `iam_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group_attrs`
--

DROP TABLE IF EXISTS `iam_group_attrs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_group_attrs` (
  `NAME` varchar(64) NOT NULL,
  `val` varchar(256) DEFAULT NULL,
  `group_id` bigint(20) DEFAULT NULL,
  KEY `INDEX_iam_group_attrs_name` (`NAME`),
  KEY `INDEX_iam_group_attrs_name_val` (`NAME`,`val`),
  KEY `FK_iam_group_attrs_group_id` (`group_id`),
  CONSTRAINT `FK_iam_group_attrs_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_group_labels` (
  `NAME` varchar(64) NOT NULL,
  `PREFIX` varchar(256) DEFAULT NULL,
  `val` varchar(64) DEFAULT NULL,
  `group_id` bigint(20) DEFAULT NULL,
  KEY `INDEX_iam_group_labels_prefix_name_val` (`PREFIX`,`NAME`,`val`),
  KEY `INDEX_iam_group_labels_prefix_name` (`PREFIX`,`NAME`),
  KEY `FK_iam_group_labels_group_id` (`group_id`),
  CONSTRAINT `FK_iam_group_labels_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_group_labels`
--

LOCK TABLES `iam_group_labels` WRITE;
/*!40000 ALTER TABLE `iam_group_labels` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_group_labels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_group_request`
--

DROP TABLE IF EXISTS `iam_group_request`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_group_request` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `UUID` varchar(36) NOT NULL,
  `ACCOUNT_ID` bigint(20) DEFAULT NULL,
  `GROUP_ID` bigint(20) DEFAULT NULL,
  `STATUS` varchar(50) DEFAULT NULL,
  `NOTES` text,
  `MOTIVATION` text,
  `CREATIONTIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `LASTUPDATETIME` timestamp NOT NULL DEFAULT '1999-12-31 23:00:00',
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_group_request_account_id` (`ACCOUNT_ID`),
  KEY `FK_iam_group_request_group_id` (`GROUP_ID`),
  CONSTRAINT `FK_iam_group_request_account_id` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_group_request_group_id` FOREIGN KEY (`GROUP_ID`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_notification_receiver` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `NOTIFICATION_ID` bigint(20) DEFAULT NULL,
  `EMAIL_ADDRESS` varchar(254) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_notification_receiver_notification_id` (`NOTIFICATION_ID`),
  CONSTRAINT `FK_iam_notification_receiver_notification_id` FOREIGN KEY (`NOTIFICATION_ID`) REFERENCES `iam_email_notification` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_oidc_id` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `ISSUER` varchar(256) NOT NULL,
  `SUBJECT` varchar(256) NOT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_oidc_id_account_id` (`account_id`),
  CONSTRAINT `FK_iam_oidc_id_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_oidc_id`
--

LOCK TABLES `iam_oidc_id` WRITE;
/*!40000 ALTER TABLE `iam_oidc_id` DISABLE KEYS */;
INSERT INTO `iam_oidc_id` VALUES (1,'https://accounts.google.com','114132403455520317223',1),(2,'https://accounts.google.com','105440632287425289613',2),(3,'urn:test-oidc-issuer','test-user',2);
/*!40000 ALTER TABLE `iam_oidc_id` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_reg_request`
--

DROP TABLE IF EXISTS `iam_reg_request`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_reg_request` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `UUID` varchar(36) NOT NULL,
  `CREATIONTIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ACCOUNT_ID` bigint(20) DEFAULT NULL,
  `STATUS` varchar(50) DEFAULT NULL,
  `LASTUPDATETIME` timestamp NULL DEFAULT NULL,
  `notes` text,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `UUID` (`UUID`),
  KEY `FK_iam_reg_request_account_id` (`ACCOUNT_ID`),
  CONSTRAINT `FK_iam_reg_request_account_id` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_reg_request_labels` (
  `NAME` varchar(64) NOT NULL,
  `PREFIX` varchar(256) DEFAULT NULL,
  `val` varchar(64) DEFAULT NULL,
  `request_id` bigint(20) DEFAULT NULL,
  KEY `INDEX_iam_reg_request_labels_prefix_name_val` (`PREFIX`,`NAME`,`val`),
  KEY `INDEX_iam_reg_request_labels_prefix_name` (`PREFIX`,`NAME`),
  KEY `FK_iam_reg_request_labels_request_id` (`request_id`),
  CONSTRAINT `FK_iam_reg_request_labels_request_id` FOREIGN KEY (`request_id`) REFERENCES `iam_reg_request` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_reg_request_labels`
--

LOCK TABLES `iam_reg_request_labels` WRITE;
/*!40000 ALTER TABLE `iam_reg_request_labels` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_reg_request_labels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_saml_id`
--

DROP TABLE IF EXISTS `iam_saml_id`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_saml_id` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `IDPID` varchar(256) NOT NULL,
  `USERID` varchar(256) NOT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  `attribute_id` varchar(256) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `FK_iam_saml_id_account_id` (`account_id`),
  KEY `IDX_IAM_SAML_ID_1` (`IDPID`,`attribute_id`,`USERID`),
  CONSTRAINT `FK_iam_saml_id_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_scope_policy` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `creation_time` datetime NOT NULL,
  `description` varchar(512) DEFAULT NULL,
  `last_update_time` datetime NOT NULL,
  `rule` varchar(6) NOT NULL,
  `account_id` bigint(20) DEFAULT NULL,
  `group_id` bigint(20) DEFAULT NULL,
  `matching_policy` varchar(6) NOT NULL DEFAULT 'EQ',
  PRIMARY KEY (`ID`),
  KEY `FK_iam_scope_policy_group_id` (`group_id`),
  KEY `FK_iam_scope_policy_account_id` (`account_id`),
  CONSTRAINT `FK_iam_scope_policy_account_id` FOREIGN KEY (`account_id`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_scope_policy_group_id` FOREIGN KEY (`group_id`) REFERENCES `iam_group` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_scope_policy`
--

LOCK TABLES `iam_scope_policy` WRITE;
/*!40000 ALTER TABLE `iam_scope_policy` DISABLE KEYS */;
INSERT INTO `iam_scope_policy` VALUES (1,'2021-12-04 17:05:42','Default Permit ALL policy','2021-12-04 17:05:42','PERMIT',NULL,NULL,'EQ');
/*!40000 ALTER TABLE `iam_scope_policy` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_scope_policy_scope`
--

DROP TABLE IF EXISTS `iam_scope_policy_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_scope_policy_scope` (
  `policy_id` bigint(20) DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL,
  UNIQUE KEY `INDEX_iam_scope_policy_scope_policy_id_scope` (`policy_id`,`scope`),
  KEY `INDEX_iam_scope_policy_scope_scope` (`scope`),
  CONSTRAINT `FK_iam_scope_policy_scope_policy_id` FOREIGN KEY (`policy_id`) REFERENCES `iam_scope_policy` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_scope_policy_scope`
--

LOCK TABLES `iam_scope_policy_scope` WRITE;
/*!40000 ALTER TABLE `iam_scope_policy_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_scope_policy_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_ssh_key`
--

DROP TABLE IF EXISTS `iam_ssh_key`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_ssh_key` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `fingerprint` varchar(48) NOT NULL,
  `LABEL` varchar(36) NOT NULL,
  `is_primary` tinyint(1) DEFAULT '0',
  `val` longtext,
  `ACCOUNT_ID` bigint(20) DEFAULT NULL,
  `creation_time` datetime NOT NULL,
  `last_update_time` datetime NOT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `fingerprint` (`fingerprint`),
  KEY `FK_iam_ssh_key_ACCOUNT_ID` (`ACCOUNT_ID`),
  CONSTRAINT `FK_iam_ssh_key_ACCOUNT_ID` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_ssh_key`
--

LOCK TABLES `iam_ssh_key` WRITE;
/*!40000 ALTER TABLE `iam_ssh_key` DISABLE KEYS */;
/*!40000 ALTER TABLE `iam_ssh_key` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_user_info`
--

DROP TABLE IF EXISTS `iam_user_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_user_info` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
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
  `ADDRESS_ID` bigint(20) DEFAULT NULL,
  `DTYPE` varchar(31) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  KEY `iui_em_idx` (`EMAIL`),
  KEY `iui_gn_fn_idx` (`GIVENNAME`,`FAMILYNAME`),
  KEY `FK_iam_user_info_address_id` (`ADDRESS_ID`),
  CONSTRAINT `FK_iam_user_info_address_id` FOREIGN KEY (`ADDRESS_ID`) REFERENCES `iam_address` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=348 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_user_info`
--

LOCK TABLES `iam_user_info` WRITE;
/*!40000 ALTER TABLE `iam_user_info` DISABLE KEYS */;
INSERT INTO `iam_user_info` VALUES (1,'1950-01-01','1_admin@iam.test',1,'User','M','Admin',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(2,'1950-01-01','test@iam.test',1,'User','M','Test',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(3,'1950-01-01','3_admin@iam.test',1,'Email 0','M','Duplicate',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(4,'1950-01-01','4_duplicate@iam.test',1,'Email 1','M','Duplicate ',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(5,'1950-01-01','5_duplicate@iam.test',1,'Email 2','M','Duplicate ',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(100,NULL,'test-100@test.org',1,'User',NULL,'Test-100',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(101,NULL,'test-101@test.org',1,'User',NULL,'Test-101',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(102,NULL,'test-102@test.org',1,'User',NULL,'Test-102',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(103,NULL,'test-103@test.org',1,'User',NULL,'Test-103',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(104,NULL,'test-104@test.org',1,'User',NULL,'Test-104',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(105,NULL,'test-105@test.org',1,'User',NULL,'Test-105',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(106,NULL,'test-106@test.org',1,'User',NULL,'Test-106',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(107,NULL,'test-107@test.org',1,'User',NULL,'Test-107',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(108,NULL,'test-108@test.org',1,'User',NULL,'Test-108',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(109,NULL,'test-109@test.org',1,'User',NULL,'Test-109',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(110,NULL,'test-110@test.org',1,'User',NULL,'Test-110',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(111,NULL,'test-111@test.org',1,'User',NULL,'Test-111',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(112,NULL,'test-112@test.org',1,'User',NULL,'Test-112',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(113,NULL,'test-113@test.org',1,'User',NULL,'Test-113',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(114,NULL,'test-114@test.org',1,'User',NULL,'Test-114',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(115,NULL,'test-115@test.org',1,'User',NULL,'Test-115',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(116,NULL,'test-116@test.org',1,'User',NULL,'Test-116',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(117,NULL,'test-117@test.org',1,'User',NULL,'Test-117',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(118,NULL,'test-118@test.org',1,'User',NULL,'Test-118',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(119,NULL,'test-119@test.org',1,'User',NULL,'Test-119',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(120,NULL,'test-120@test.org',1,'User',NULL,'Test-120',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(121,NULL,'test-121@test.org',1,'User',NULL,'Test-121',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(122,NULL,'test-122@test.org',1,'User',NULL,'Test-122',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(123,NULL,'test-123@test.org',1,'User',NULL,'Test-123',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(124,NULL,'test-124@test.org',1,'User',NULL,'Test-124',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(125,NULL,'test-125@test.org',1,'User',NULL,'Test-125',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(126,NULL,'test-126@test.org',1,'User',NULL,'Test-126',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(127,NULL,'test-127@test.org',1,'User',NULL,'Test-127',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(128,NULL,'test-128@test.org',1,'User',NULL,'Test-128',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(129,NULL,'test-129@test.org',1,'User',NULL,'Test-129',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(130,NULL,'test-130@test.org',1,'User',NULL,'Test-130',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(131,NULL,'test-131@test.org',1,'User',NULL,'Test-131',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(132,NULL,'test-132@test.org',1,'User',NULL,'Test-132',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(133,NULL,'test-133@test.org',1,'User',NULL,'Test-133',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(134,NULL,'test-134@test.org',1,'User',NULL,'Test-134',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(135,NULL,'test-135@test.org',1,'User',NULL,'Test-135',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(136,NULL,'test-136@test.org',1,'User',NULL,'Test-136',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(137,NULL,'test-137@test.org',1,'User',NULL,'Test-137',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(138,NULL,'test-138@test.org',1,'User',NULL,'Test-138',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(139,NULL,'test-139@test.org',1,'User',NULL,'Test-139',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(140,NULL,'test-140@test.org',1,'User',NULL,'Test-140',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(141,NULL,'test-141@test.org',1,'User',NULL,'Test-141',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(142,NULL,'test-142@test.org',1,'User',NULL,'Test-142',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(143,NULL,'test-143@test.org',1,'User',NULL,'Test-143',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(144,NULL,'test-144@test.org',1,'User',NULL,'Test-144',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(145,NULL,'test-145@test.org',1,'User',NULL,'Test-145',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(146,NULL,'test-146@test.org',1,'User',NULL,'Test-146',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(147,NULL,'test-147@test.org',1,'User',NULL,'Test-147',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(148,NULL,'test-148@test.org',1,'User',NULL,'Test-148',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(149,NULL,'test-149@test.org',1,'User',NULL,'Test-149',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(150,NULL,'test-150@test.org',1,'User',NULL,'Test-150',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(151,NULL,'test-151@test.org',1,'User',NULL,'Test-151',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(152,NULL,'test-152@test.org',1,'User',NULL,'Test-152',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(153,NULL,'test-153@test.org',1,'User',NULL,'Test-153',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(154,NULL,'test-154@test.org',1,'User',NULL,'Test-154',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(155,NULL,'test-155@test.org',1,'User',NULL,'Test-155',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(156,NULL,'test-156@test.org',1,'User',NULL,'Test-156',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(157,NULL,'test-157@test.org',1,'User',NULL,'Test-157',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(158,NULL,'test-158@test.org',1,'User',NULL,'Test-158',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(159,NULL,'test-159@test.org',1,'User',NULL,'Test-159',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(160,NULL,'test-160@test.org',1,'User',NULL,'Test-160',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(161,NULL,'test-161@test.org',1,'User',NULL,'Test-161',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(162,NULL,'test-162@test.org',1,'User',NULL,'Test-162',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(163,NULL,'test-163@test.org',1,'User',NULL,'Test-163',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(164,NULL,'test-164@test.org',1,'User',NULL,'Test-164',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(165,NULL,'test-165@test.org',1,'User',NULL,'Test-165',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(166,NULL,'test-166@test.org',1,'User',NULL,'Test-166',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(167,NULL,'test-167@test.org',1,'User',NULL,'Test-167',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(168,NULL,'test-168@test.org',1,'User',NULL,'Test-168',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(169,NULL,'test-169@test.org',1,'User',NULL,'Test-169',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(170,NULL,'test-170@test.org',1,'User',NULL,'Test-170',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(171,NULL,'test-171@test.org',1,'User',NULL,'Test-171',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(172,NULL,'test-172@test.org',1,'User',NULL,'Test-172',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(173,NULL,'test-173@test.org',1,'User',NULL,'Test-173',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(174,NULL,'test-174@test.org',1,'User',NULL,'Test-174',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(175,NULL,'test-175@test.org',1,'User',NULL,'Test-175',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(176,NULL,'test-176@test.org',1,'User',NULL,'Test-176',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(177,NULL,'test-177@test.org',1,'User',NULL,'Test-177',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(178,NULL,'test-178@test.org',1,'User',NULL,'Test-178',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(179,NULL,'test-179@test.org',1,'User',NULL,'Test-179',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(180,NULL,'test-180@test.org',1,'User',NULL,'Test-180',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(181,NULL,'test-181@test.org',1,'User',NULL,'Test-181',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(182,NULL,'test-182@test.org',1,'User',NULL,'Test-182',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(183,NULL,'test-183@test.org',1,'User',NULL,'Test-183',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(184,NULL,'test-184@test.org',1,'User',NULL,'Test-184',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(185,NULL,'test-185@test.org',1,'User',NULL,'Test-185',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(186,NULL,'test-186@test.org',1,'User',NULL,'Test-186',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(187,NULL,'test-187@test.org',1,'User',NULL,'Test-187',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(188,NULL,'test-188@test.org',1,'User',NULL,'Test-188',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(189,NULL,'test-189@test.org',1,'User',NULL,'Test-189',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(190,NULL,'test-190@test.org',1,'User',NULL,'Test-190',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(191,NULL,'test-191@test.org',1,'User',NULL,'Test-191',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(192,NULL,'test-192@test.org',1,'User',NULL,'Test-192',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(193,NULL,'test-193@test.org',1,'User',NULL,'Test-193',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(194,NULL,'test-194@test.org',1,'User',NULL,'Test-194',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(195,NULL,'test-195@test.org',1,'User',NULL,'Test-195',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(196,NULL,'test-196@test.org',1,'User',NULL,'Test-196',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(197,NULL,'test-197@test.org',1,'User',NULL,'Test-197',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(198,NULL,'test-198@test.org',1,'User',NULL,'Test-198',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(199,NULL,'test-199@test.org',1,'User',NULL,'Test-199',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(200,NULL,'test-200@test.org',1,'User',NULL,'Test-200',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(201,NULL,'test-201@test.org',1,'User',NULL,'Test-201',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(202,NULL,'test-202@test.org',1,'User',NULL,'Test-202',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(203,NULL,'test-203@test.org',1,'User',NULL,'Test-203',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(204,NULL,'test-204@test.org',1,'User',NULL,'Test-204',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(205,NULL,'test-205@test.org',1,'User',NULL,'Test-205',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(206,NULL,'test-206@test.org',1,'User',NULL,'Test-206',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(207,NULL,'test-207@test.org',1,'User',NULL,'Test-207',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(208,NULL,'test-208@test.org',1,'User',NULL,'Test-208',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(209,NULL,'test-209@test.org',1,'User',NULL,'Test-209',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(210,NULL,'test-210@test.org',1,'User',NULL,'Test-210',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(211,NULL,'test-211@test.org',1,'User',NULL,'Test-211',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(212,NULL,'test-212@test.org',1,'User',NULL,'Test-212',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(213,NULL,'test-213@test.org',1,'User',NULL,'Test-213',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(214,NULL,'test-214@test.org',1,'User',NULL,'Test-214',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(215,NULL,'test-215@test.org',1,'User',NULL,'Test-215',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(216,NULL,'test-216@test.org',1,'User',NULL,'Test-216',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(217,NULL,'test-217@test.org',1,'User',NULL,'Test-217',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(218,NULL,'test-218@test.org',1,'User',NULL,'Test-218',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(219,NULL,'test-219@test.org',1,'User',NULL,'Test-219',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(220,NULL,'test-220@test.org',1,'User',NULL,'Test-220',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(221,NULL,'test-221@test.org',1,'User',NULL,'Test-221',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(222,NULL,'test-222@test.org',1,'User',NULL,'Test-222',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(223,NULL,'test-223@test.org',1,'User',NULL,'Test-223',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(224,NULL,'test-224@test.org',1,'User',NULL,'Test-224',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(225,NULL,'test-225@test.org',1,'User',NULL,'Test-225',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(226,NULL,'test-226@test.org',1,'User',NULL,'Test-226',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(227,NULL,'test-227@test.org',1,'User',NULL,'Test-227',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(228,NULL,'test-228@test.org',1,'User',NULL,'Test-228',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(229,NULL,'test-229@test.org',1,'User',NULL,'Test-229',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(230,NULL,'test-230@test.org',1,'User',NULL,'Test-230',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(231,NULL,'test-231@test.org',1,'User',NULL,'Test-231',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(232,NULL,'test-232@test.org',1,'User',NULL,'Test-232',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(233,NULL,'test-233@test.org',1,'User',NULL,'Test-233',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(234,NULL,'test-234@test.org',1,'User',NULL,'Test-234',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(235,NULL,'test-235@test.org',1,'User',NULL,'Test-235',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(236,NULL,'test-236@test.org',1,'User',NULL,'Test-236',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(237,NULL,'test-237@test.org',1,'User',NULL,'Test-237',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(238,NULL,'test-238@test.org',1,'User',NULL,'Test-238',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(239,NULL,'test-239@test.org',1,'User',NULL,'Test-239',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(240,NULL,'test-240@test.org',1,'User',NULL,'Test-240',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(241,NULL,'test-241@test.org',1,'User',NULL,'Test-241',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(242,NULL,'test-242@test.org',1,'User',NULL,'Test-242',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(243,NULL,'test-243@test.org',1,'User',NULL,'Test-243',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(244,NULL,'test-244@test.org',1,'User',NULL,'Test-244',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(245,NULL,'test-245@test.org',1,'User',NULL,'Test-245',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(246,NULL,'test-246@test.org',1,'User',NULL,'Test-246',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(247,NULL,'test-247@test.org',1,'User',NULL,'Test-247',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(248,NULL,'test-248@test.org',1,'User',NULL,'Test-248',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(249,NULL,'test-249@test.org',1,'User',NULL,'Test-249',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(250,NULL,'test-250@test.org',1,'User',NULL,'Test-250',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(251,NULL,'test-251@test.org',1,'User',NULL,'Test-251',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(252,NULL,'test-252@test.org',1,'User',NULL,'Test-252',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(253,NULL,'test-253@test.org',1,'User',NULL,'Test-253',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(254,NULL,'test-254@test.org',1,'User',NULL,'Test-254',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(255,NULL,'test-255@test.org',1,'User',NULL,'Test-255',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(256,NULL,'test-256@test.org',1,'User',NULL,'Test-256',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(257,NULL,'test-257@test.org',1,'User',NULL,'Test-257',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(258,NULL,'test-258@test.org',1,'User',NULL,'Test-258',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(259,NULL,'test-259@test.org',1,'User',NULL,'Test-259',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(260,NULL,'test-260@test.org',1,'User',NULL,'Test-260',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(261,NULL,'test-261@test.org',1,'User',NULL,'Test-261',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(262,NULL,'test-262@test.org',1,'User',NULL,'Test-262',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(263,NULL,'test-263@test.org',1,'User',NULL,'Test-263',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(264,NULL,'test-264@test.org',1,'User',NULL,'Test-264',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(265,NULL,'test-265@test.org',1,'User',NULL,'Test-265',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(266,NULL,'test-266@test.org',1,'User',NULL,'Test-266',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(267,NULL,'test-267@test.org',1,'User',NULL,'Test-267',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(268,NULL,'test-268@test.org',1,'User',NULL,'Test-268',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(269,NULL,'test-269@test.org',1,'User',NULL,'Test-269',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(270,NULL,'test-270@test.org',1,'User',NULL,'Test-270',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(271,NULL,'test-271@test.org',1,'User',NULL,'Test-271',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(272,NULL,'test-272@test.org',1,'User',NULL,'Test-272',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(273,NULL,'test-273@test.org',1,'User',NULL,'Test-273',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(274,NULL,'test-274@test.org',1,'User',NULL,'Test-274',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(275,NULL,'test-275@test.org',1,'User',NULL,'Test-275',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(276,NULL,'test-276@test.org',1,'User',NULL,'Test-276',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(277,NULL,'test-277@test.org',1,'User',NULL,'Test-277',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(278,NULL,'test-278@test.org',1,'User',NULL,'Test-278',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(279,NULL,'test-279@test.org',1,'User',NULL,'Test-279',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(280,NULL,'test-280@test.org',1,'User',NULL,'Test-280',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(281,NULL,'test-281@test.org',1,'User',NULL,'Test-281',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(282,NULL,'test-282@test.org',1,'User',NULL,'Test-282',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(283,NULL,'test-283@test.org',1,'User',NULL,'Test-283',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(284,NULL,'test-284@test.org',1,'User',NULL,'Test-284',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(285,NULL,'test-285@test.org',1,'User',NULL,'Test-285',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(286,NULL,'test-286@test.org',1,'User',NULL,'Test-286',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(287,NULL,'test-287@test.org',1,'User',NULL,'Test-287',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(288,NULL,'test-288@test.org',1,'User',NULL,'Test-288',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(289,NULL,'test-289@test.org',1,'User',NULL,'Test-289',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(290,NULL,'test-290@test.org',1,'User',NULL,'Test-290',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(291,NULL,'test-291@test.org',1,'User',NULL,'Test-291',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(292,NULL,'test-292@test.org',1,'User',NULL,'Test-292',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(293,NULL,'test-293@test.org',1,'User',NULL,'Test-293',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(294,NULL,'test-294@test.org',1,'User',NULL,'Test-294',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(295,NULL,'test-295@test.org',1,'User',NULL,'Test-295',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(296,NULL,'test-296@test.org',1,'User',NULL,'Test-296',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(297,NULL,'test-297@test.org',1,'User',NULL,'Test-297',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(298,NULL,'test-298@test.org',1,'User',NULL,'Test-298',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(299,NULL,'test-299@test.org',1,'User',NULL,'Test-299',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(300,NULL,'test-300@test.org',1,'User',NULL,'Test-300',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(301,NULL,'test-301@test.org',1,'User',NULL,'Test-301',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(302,NULL,'test-302@test.org',1,'User',NULL,'Test-302',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(303,NULL,'test-303@test.org',1,'User',NULL,'Test-303',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(304,NULL,'test-304@test.org',1,'User',NULL,'Test-304',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(305,NULL,'test-305@test.org',1,'User',NULL,'Test-305',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(306,NULL,'test-306@test.org',1,'User',NULL,'Test-306',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(307,NULL,'test-307@test.org',1,'User',NULL,'Test-307',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(308,NULL,'test-308@test.org',1,'User',NULL,'Test-308',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(309,NULL,'test-309@test.org',1,'User',NULL,'Test-309',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(310,NULL,'test-310@test.org',1,'User',NULL,'Test-310',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(311,NULL,'test-311@test.org',1,'User',NULL,'Test-311',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(312,NULL,'test-312@test.org',1,'User',NULL,'Test-312',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(313,NULL,'test-313@test.org',1,'User',NULL,'Test-313',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(314,NULL,'test-314@test.org',1,'User',NULL,'Test-314',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(315,NULL,'test-315@test.org',1,'User',NULL,'Test-315',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(316,NULL,'test-316@test.org',1,'User',NULL,'Test-316',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(317,NULL,'test-317@test.org',1,'User',NULL,'Test-317',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(318,NULL,'test-318@test.org',1,'User',NULL,'Test-318',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(319,NULL,'test-319@test.org',1,'User',NULL,'Test-319',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(320,NULL,'test-320@test.org',1,'User',NULL,'Test-320',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(321,NULL,'test-321@test.org',1,'User',NULL,'Test-321',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(322,NULL,'test-322@test.org',1,'User',NULL,'Test-322',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(323,NULL,'test-323@test.org',1,'User',NULL,'Test-323',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(324,NULL,'test-324@test.org',1,'User',NULL,'Test-324',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(325,NULL,'test-325@test.org',1,'User',NULL,'Test-325',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(326,NULL,'test-326@test.org',1,'User',NULL,'Test-326',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(327,NULL,'test-327@test.org',1,'User',NULL,'Test-327',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(328,NULL,'test-328@test.org',1,'User',NULL,'Test-328',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(329,NULL,'test-329@test.org',1,'User',NULL,'Test-329',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(330,NULL,'test-330@test.org',1,'User',NULL,'Test-330',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(331,NULL,'test-331@test.org',1,'User',NULL,'Test-331',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(332,NULL,'test-332@test.org',1,'User',NULL,'Test-332',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(333,NULL,'test-333@test.org',1,'User',NULL,'Test-333',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(334,NULL,'test-334@test.org',1,'User',NULL,'Test-334',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(335,NULL,'test-335@test.org',1,'User',NULL,'Test-335',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(336,NULL,'test-336@test.org',1,'User',NULL,'Test-336',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(337,NULL,'test-337@test.org',1,'User',NULL,'Test-337',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(338,NULL,'test-338@test.org',1,'User',NULL,'Test-338',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(339,NULL,'test-339@test.org',1,'User',NULL,'Test-339',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(340,NULL,'test-340@test.org',1,'User',NULL,'Test-340',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(341,NULL,'test-341@test.org',1,'User',NULL,'Test-341',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(342,NULL,'test-342@test.org',1,'User',NULL,'Test-342',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(343,NULL,'test-343@test.org',1,'User',NULL,'Test-343',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(344,NULL,'test-344@test.org',1,'User',NULL,'Test-344',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(345,NULL,'test-345@test.org',1,'User',NULL,'Test-345',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(346,NULL,'test-346@test.org',1,'User',NULL,'Test-346',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL),(347,NULL,'test-347@test.org',1,'User',NULL,'Test-347',NULL,NULL,NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL);
/*!40000 ALTER TABLE `iam_user_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_x509_cert`
--

DROP TABLE IF EXISTS `iam_x509_cert`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_x509_cert` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `subject_dn` varchar(256) DEFAULT NULL,
  `LABEL` varchar(36) NOT NULL,
  `is_primary` tinyint(1) DEFAULT '0',
  `ACCOUNT_ID` bigint(20) DEFAULT NULL,
  `CERTIFICATE` text,
  `issuer_dn` varchar(256) DEFAULT NULL,
  `creation_time` datetime NOT NULL,
  `last_update_time` datetime NOT NULL,
  `proxy_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `subject_dn` (`subject_dn`),
  UNIQUE KEY `idx_iam_x509_cert_cerificate` (`CERTIFICATE`(256)),
  KEY `FK_iam_x509_cert_ACCOUNT_ID` (`ACCOUNT_ID`),
  KEY `FK_iam_x509_cert_proxy_id` (`proxy_id`),
  CONSTRAINT `FK_iam_x509_cert_ACCOUNT_ID` FOREIGN KEY (`ACCOUNT_ID`) REFERENCES `iam_account` (`ID`),
  CONSTRAINT `FK_iam_x509_cert_proxy_id` FOREIGN KEY (`proxy_id`) REFERENCES `iam_x509_proxy` (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `iam_x509_cert`
--

LOCK TABLES `iam_x509_cert` WRITE;
/*!40000 ALTER TABLE `iam_x509_cert` DISABLE KEYS */;
INSERT INTO `iam_x509_cert` VALUES (1,'CN=test2,O=IGI,C=IT','test2 cert',1,1,'-----BEGIN CERTIFICATE-----\nMIIDnjCCAoagAwIBAgIBCzANBgkqhkiG9w0BAQUFADAtMQswCQYDVQQGEwJJVDEM\nMAoGA1UECgwDSUdJMRAwDgYDVQQDDAdUZXN0IENBMB4XDTEyMDkyNjE1MzkzOFoX\nDTIyMDkyNDE1MzkzOFowKzELMAkGA1UEBhMCSVQxDDAKBgNVBAoTA0lHSTEOMAwG\nA1UEAxMFdGVzdDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEYYwo\neq5ucXGsIZqI5V30OmEZTLzz3TCtFSp+DWbFHAeiiZNNktK44udHV+kwTjSxHTUJ\nP9RIvCAIMggtvibesXrTp1UHAF6p1d2GaUmU+mc/y7zRESxuSXx+SqWCwBOVxOzj\nDhm9oWlg3TSNctV2qv0HR2t8hsnfsQShULwaUJmQZ1fBfDN6HL5ITe77ptXB84Hz\nMAmNv0ckoQmVGtlVhoasppTgMhoWvBSguT1FGw7A/a8ZzQZV8rC1BP/1LZtRitHm\nstErUyULBjQekpu3VhGFJLCFD3fcyjoBKsIxCm62NhzHLOF8RE+kW05MRGrUu007\nCuV3yCDZOixIAxKVAgMBAAGjgcowgccwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU\nXNkN/hv+aBr6hqNqYm1VaiEAvpcwDgYDVR0PAQH/BAQDAgXgMD4GA1UdJQQ3MDUG\nCCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBBggrBgEF\nBQcDBDAfBgNVHSMEGDAWgBSRdzZ7LrRp8yfqt/YIi0ojohFJxjAnBgNVHREEIDAe\ngRxhbmRyZWEuY2VjY2FudGlAY25hZi5pbmZuLml0MA0GCSqGSIb3DQEBBQUAA4IB\nAQBOavmIRcBqWnGFmcEp8zJ+cR3k02UcM0Xg7/vAnxJ7JziniMJLyBrxAaW1j2f6\nqJrap9rK+aukhovInTSrdWKM6y5ceY0w7u4nsu8Y3lRf3g9e766iuY3NfflDZE2N\ns3JuHZljwx7NGEOrr/Wi5Q1g9JVJcK+A+aB3vPLoS/Uc95ibdqJKHVG0rcKLnqR6\nAVvzyPxJtpwk4yy4V+juBZib2SImBWJ7C5VHuHLMAOxtNV84CIXpdvLKfA1Bjf3W\nUMrcvhN03L72j9IR0WEZlFMfYbxv1gbNbo+fhVo3itHI3lTl0K0BD5bOP0LqtARL\ngZ9zFVlxWHcKUqQ41ZQXNg7U\n-----END CERTIFICATE-----','CN=Test CA,O=IGI,C=IT','2021-12-04 17:05:45','2021-12-04 17:05:45',NULL);
/*!40000 ALTER TABLE `iam_x509_cert` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `iam_x509_proxy`
--

DROP TABLE IF EXISTS `iam_x509_proxy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `iam_x509_proxy` (
  `ID` bigint(20) NOT NULL AUTO_INCREMENT,
  `CHAIN` longtext NOT NULL,
  `exp_time` datetime NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `IDX_IAM_X509_PXY_EXP_T` (`exp_time`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pairwise_identifier` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `identifier` varchar(256) DEFAULT NULL,
  `sub` varchar(256) DEFAULT NULL,
  `sector_identifier` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `permission` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `resource_set_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `permission_scope` (
  `owner_id` bigint(20) NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `permission_ticket` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ticket` varchar(256) NOT NULL,
  `permission_id` bigint(20) NOT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `policy` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) DEFAULT NULL,
  `resource_set_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `policy_scope` (
  `owner_id` bigint(20) NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `refresh_token` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `token_value` varchar(4096) DEFAULT NULL,
  `expiration` timestamp NULL DEFAULT NULL,
  `auth_holder_id` bigint(20) DEFAULT NULL,
  `client_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `rf_ahi_idx` (`auth_holder_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `refresh_token`
--

LOCK TABLES `refresh_token` WRITE;
/*!40000 ALTER TABLE `refresh_token` DISABLE KEYS */;
/*!40000 ALTER TABLE `refresh_token` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `resource_set`
--

DROP TABLE IF EXISTS `resource_set`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `resource_set` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) NOT NULL,
  `uri` varchar(1024) DEFAULT NULL,
  `icon_uri` varchar(1024) DEFAULT NULL,
  `rs_type` varchar(256) DEFAULT NULL,
  `owner` varchar(256) NOT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `resource_set_scope` (
  `owner_id` bigint(20) NOT NULL,
  `scope` varchar(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `saved_registered_client` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `issuer` varchar(1024) DEFAULT NULL,
  `registered_client` varchar(8192) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `saved_user_auth` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) DEFAULT NULL,
  `authenticated` tinyint(1) DEFAULT NULL,
  `source_class` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `saved_user_auth`
--

LOCK TABLES `saved_user_auth` WRITE;
/*!40000 ALTER TABLE `saved_user_auth` DISABLE KEYS */;
/*!40000 ALTER TABLE `saved_user_auth` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `saved_user_auth_authority`
--

DROP TABLE IF EXISTS `saved_user_auth_authority`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `saved_user_auth_authority` (
  `owner_id` bigint(20) DEFAULT NULL,
  `authority` varchar(256) DEFAULT NULL,
  KEY `suaa_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `saved_user_auth_authority`
--

LOCK TABLES `saved_user_auth_authority` WRITE;
/*!40000 ALTER TABLE `saved_user_auth_authority` DISABLE KEYS */;
/*!40000 ALTER TABLE `saved_user_auth_authority` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `saved_user_auth_info`
--

DROP TABLE IF EXISTS `saved_user_auth_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `saved_user_auth_info` (
  `owner_id` bigint(20) DEFAULT NULL,
  `info_key` varchar(256) DEFAULT NULL,
  `info_val` varchar(256) DEFAULT NULL,
  UNIQUE KEY `owner_id` (`owner_id`,`info_key`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `schema_version` (
  `version_rank` int(11) NOT NULL,
  `installed_rank` int(11) NOT NULL,
  `version` varchar(50) NOT NULL,
  `description` varchar(200) NOT NULL,
  `type` varchar(20) NOT NULL,
  `script` varchar(1000) NOT NULL,
  `checksum` int(11) DEFAULT NULL,
  `installed_by` varchar(100) NOT NULL,
  `installed_on` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `execution_time` int(11) NOT NULL,
  `success` tinyint(1) NOT NULL,
  PRIMARY KEY (`version`),
  KEY `schema_version_vr_idx` (`version_rank`),
  KEY `schema_version_ir_idx` (`installed_rank`),
  KEY `schema_version_s_idx` (`success`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `schema_version`
--

LOCK TABLES `schema_version` WRITE;
/*!40000 ALTER TABLE `schema_version` DISABLE KEYS */;
INSERT INTO `schema_version` VALUES (1,1,'1',' init','SQL','V1___init.sql',-218477982,'iam','2021-12-04 16:05:39',800,1),(11,11,'10','fix internal authz scopes','SQL','V10__fix_internal_authz_scopes.sql',-258213024,'iam','2021-12-04 16:05:40',31,1),(12,12,'10.1','Password Update','SPRING_JDBC','db.migration.mysql.V10_1__Password_Update',NULL,'iam','2021-12-04 16:05:41',695,1),(13,13,'10.2',' CheckDuplicateEmails','SPRING_JDBC','db.migration.mysql.V10_2___CheckDuplicateEmails',NULL,'iam','2021-12-04 16:05:41',33,1),(44,44,'100000',' test data','SQL','V100000___test_data.sql',1420978028,'iam','2021-12-04 16:05:45',140,1),(45,45,'100000.1',' CreateGroupManagerAuthorities','SPRING_JDBC','db.migration.test.V100000_1___CreateGroupManagerAuthorities',NULL,'iam','2021-12-04 16:05:45',51,1),(46,46,'100000.2',' test data orphan tokens','SQL','V100000_2___test_data_orphan_tokens.sql',1961674293,'iam','2021-12-04 16:05:45',40,1),(47,47,'100000.3',' RemoveOrphanTokens','SPRING_JDBC','db.migration.test.V100000_3___RemoveOrphanTokens',NULL,'iam','2021-12-04 16:05:45',18,1),(48,48,'100000.4',' remove data after orphan tokens test','SQL','V100000_4___remove_data_after_orphan_tokens_test.sql',-25223922,'iam','2021-12-04 16:05:45',37,1),(49,49,'100000.6','add eduperson scopes to client','SQL','V100000_6__add_eduperson_scopes_to_client.sql',1649437699,'iam','2021-12-04 16:05:45',16,1),(14,14,'11','fix base scim and reg scopes','SQL','V11__fix_base_scim_and_reg_scopes.sql',1865678168,'iam','2021-12-04 16:05:41',19,1),(15,15,'11.1','no attr id saml account for admin user','SQL','V11_1__no_attr_id_saml_account_for_admin_user.sql',818402938,'iam','2021-12-04 16:05:41',15,1),(16,16,'12','iam group nested groups','SQL','V12__iam_group_nested_groups.sql',-695019593,'iam','2021-12-04 16:05:41',71,1),(17,17,'13','add attribute id to saml id table','SQL','V13__add_attribute_id_to_saml_id_table.sql',-397788793,'iam','2021-12-04 16:05:42',201,1),(18,18,'14',' x509 certs table changes','SQL','V14___x509_certs_table_changes.sql',1886716498,'iam','2021-12-04 16:05:42',155,1),(19,19,'15','alter iam group','SQL','V15__alter_iam_group.sql',588116562,'iam','2021-12-04 16:05:42',47,1),(20,20,'16','add provisioned column to iam account','SQL','V16__add_provisioned_column_to_iam_account.sql',-412990673,'iam','2021-12-04 16:05:42',243,1),(21,21,'17','add scope policy tables','SQL','V17__add_scope_policy_tables.sql',-481049801,'iam','2021-12-04 16:05:42',154,1),(22,22,'18','mitre 1 3 x database changes','SQL','V18__mitre_1_3_x_database_changes.sql',-528997556,'iam','2021-12-04 16:05:42',240,1),(23,23,'19','aup tables','SQL','V19__aup_tables.sql',-150228020,'iam','2021-12-04 16:05:43',111,1),(2,2,'2',' iam tables','SQL','V2___iam_tables.sql',-413169771,'iam','2021-12-04 16:05:40',475,1),(24,24,'20','group membership request','SQL','V20__group_membership_request.sql',104090851,'iam','2021-12-04 16:05:43',90,1),(25,25,'21',' device code default expiration','SQL','V21___device_code_default_expiration.sql',965164897,'iam','2021-12-04 16:05:43',14,1),(26,26,'22','add indexes for search queries','SQL','V22__add_indexes_for_search_queries.sql',219204555,'iam','2021-12-04 16:05:43',93,1),(27,27,'23',' CreateGroupManagerAuthorities','SPRING_JDBC','db.migration.mysql.V23___CreateGroupManagerAuthorities',NULL,'iam','2021-12-04 16:05:43',16,1),(28,28,'24',' set timestamp default','SQL','V24___set_timestamp_default.sql',1496583802,'iam','2021-12-04 16:05:43',15,1),(3,3,'3','basic configuration','SQL','V3__basic_configuration.sql',-267357288,'iam','2021-12-04 16:05:40',40,1),(4,4,'3.1',' duplicate email user','SQL','V3_1___duplicate_email_user.sql',66200834,'iam','2021-12-04 16:05:40',34,1),(29,29,'30',' default group support','SQL','V30___default_group_support.sql',258640485,'iam','2021-12-04 16:05:43',350,1),(30,30,'31',' address table fixes','SQL','V31___address_table_fixes.sql',366658476,'iam','2021-12-04 16:05:43',116,1),(31,31,'32',' proxy storage','SQL','V32___proxy_storage.sql',-115324393,'iam','2021-12-04 16:05:44',100,1),(32,32,'33',' proxy api scopes','SQL','V33___proxy_api_scopes.sql',-819610666,'iam','2021-12-04 16:05:44',17,1),(33,33,'34',' req request labels','SQL','V34___req_request_labels.sql',-1368451960,'iam','2021-12-04 16:05:44',88,1),(34,34,'34.2',' RemoveOrphanTokens','SPRING_JDBC','db.migration.mysql.V34_2___RemoveOrphanTokens',NULL,'iam','2021-12-04 16:05:44',16,1),(35,35,'35',' scope match policies','SQL','V35___scope_match_policies.sql',511076879,'iam','2021-12-04 16:05:44',189,1),(5,5,'4',' x509 updates','SQL','V4___x509_updates.sql',803590936,'iam','2021-12-04 16:05:40',39,1),(36,36,'40',' aup updates','SQL','V40___aup_updates.sql',-931983135,'iam','2021-12-04 16:05:44',58,1),(6,6,'5',' registration request','SQL','V5___registration_request.sql',-1289707463,'iam','2021-12-04 16:05:40',129,1),(37,37,'50',' token exchange policy','SQL','V50___token_exchange_policy.sql',-688052057,'iam','2021-12-04 16:05:44',71,1),(38,38,'51',' fix scope match policies','SQL','V51___fix_scope_match_policies.sql',647108568,'iam','2021-12-04 16:05:44',20,1),(39,39,'52','add eduperson system scopes','SQL','V52__add_eduperson_system_scopes.sql',553473571,'iam','2021-12-04 16:05:44',16,1),(40,40,'53',' add end time to iam acccount','SQL','V53___add_end_time_to_iam_acccount.sql',-1585752792,'iam','2021-12-04 16:05:44',111,1),(7,7,'6',' remove wrong constraints','SQL','V6___remove_wrong_constraints.sql',1072876395,'iam','2021-12-04 16:05:40',29,1),(41,41,'60',' fix certificate subject length','SQL','V60___fix_certificate_subject_length.sql',582827795,'iam','2021-12-04 16:05:44',82,1),(42,42,'61',' add dates for group membership','SQL','V61___add_dates_for_group_membership.sql',939528754,'iam','2021-12-04 16:05:45',56,1),(43,43,'62',' add dates to ssh keys table','SQL','V62___add_dates_to_ssh_keys_table.sql',1905011270,'iam','2021-12-04 16:05:45',67,1),(8,8,'7',' notification tables','SQL','V7___notification_tables.sql',-1698909137,'iam','2021-12-04 16:05:40',128,1),(9,9,'8',' mitre update','SQL','V8___mitre_update.sql',608617254,'iam','2021-12-04 16:05:40',35,1),(10,10,'9','mitre saved user authn changes','SQL','V9__mitre_saved_user_authn_changes.sql',-1153995430,'iam','2021-12-04 16:05:40',28,1);
/*!40000 ALTER TABLE `schema_version` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `system_scope`
--

DROP TABLE IF EXISTS `system_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `system_scope` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `scope` varchar(256) NOT NULL,
  `description` varchar(4096) DEFAULT NULL,
  `icon` varchar(256) DEFAULT NULL,
  `restricted` tinyint(1) NOT NULL DEFAULT '0',
  `default_scope` tinyint(1) NOT NULL DEFAULT '0',
  `structured` tinyint(1) NOT NULL DEFAULT '0',
  `structured_param_description` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `scope` (`scope`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `system_scope`
--

LOCK TABLES `system_scope` WRITE;
/*!40000 ALTER TABLE `system_scope` DISABLE KEYS */;
INSERT INTO `system_scope` VALUES (1,'openid','log in using your identity','user',0,1,0,NULL),(2,'profile','basic profile information','list-alt',0,1,0,NULL),(3,'email','email address','envelope',0,1,0,NULL),(4,'address','physical address','home',0,1,0,NULL),(5,'phone','telephone number','bell',0,1,0,NULL),(6,'offline_access','offline access','time',0,0,0,NULL),(7,'scim:read','read access to SCIM user and groups',NULL,1,0,1,'read access to IAM SCIM APIs'),(8,'scim:write','write access to SCIM user and groups',NULL,1,0,1,'write access to IAM SCIM APIs'),(9,'registration:read','Grants read access to registration requests',NULL,1,0,1,'read access to IAM registration APIs'),(10,'registration:write','Grants write access to registration requests',NULL,1,0,1,'write access to IAM registration APIs'),(11,'scim','Authorizes access to IAM SCIM APIs',NULL,1,0,1,NULL),(12,'registration','Authorizes access to IAM registration APIs',NULL,1,0,1,NULL),(13,'proxy:generate','Authorizes access to IAM Proxy APIs',NULL,1,0,1,NULL),(16,'eduperson_scoped_affiliation','Access to EduPerson scoped affiliation information',NULL,0,0,0,NULL),(17,'eduperson_entitlement','Access to EduPerson entitlements information',NULL,0,0,0,NULL),(18,'ssh-keys','Authorizes access to SSH keys linked to IAM accounts via the IAM userinfo endpoint',NULL,1,0,1,NULL);
/*!40000 ALTER TABLE `system_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `token_scope`
--

DROP TABLE IF EXISTS `token_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `token_scope` (
  `owner_id` bigint(20) DEFAULT NULL,
  `scope` varchar(2048) DEFAULT NULL,
  KEY `ts_oi_idx` (`owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `token_scope`
--

LOCK TABLES `token_scope` WRITE;
/*!40000 ALTER TABLE `token_scope` DISABLE KEYS */;
/*!40000 ALTER TABLE `token_scope` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_info`
--

DROP TABLE IF EXISTS `user_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_info` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
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
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
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
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `whitelisted_site` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `creator_user_id` varchar(256) DEFAULT NULL,
  `client_id` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `whitelisted_site`
--

LOCK TABLES `whitelisted_site` WRITE;
/*!40000 ALTER TABLE `whitelisted_site` DISABLE KEYS */;
/*!40000 ALTER TABLE `whitelisted_site` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `whitelisted_site_scope`
--

DROP TABLE IF EXISTS `whitelisted_site_scope`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `whitelisted_site_scope` (
  `owner_id` bigint(20) DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `whitelisted_site_scope`
--

LOCK TABLES `whitelisted_site_scope` WRITE;
/*!40000 ALTER TABLE `whitelisted_site_scope` DISABLE KEYS */;
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

-- Dump completed on 2021-12-04 16:07:45
