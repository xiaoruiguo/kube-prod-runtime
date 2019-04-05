/*
 * Bitnami Kubernetes Production Runtime - A collection of services that makes it
 * easy to run production workloads in Kubernetes.
 *
 * Copyright 2019 Bitnami
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Top-level file for AWS EKS

local kube = import "../lib/kube.libsonnet";
local kubecfg = import "kubecfg.libsonnet";
local utils = import "../lib/utils.libsonnet";
local version = import "../components/version.jsonnet";
local cert_manager = import "../components/cert-manager.jsonnet";
local edns = import "../components/externaldns.jsonnet";
local nginx_ingress = import "../components/nginx-ingress.jsonnet";
local prometheus = import "../components/prometheus.jsonnet";
local oauth2_proxy = import "../components/oauth2-proxy.jsonnet";
local fluentd_es = import "../components/fluentd-es.jsonnet";
local elasticsearch = import "../components/elasticsearch.jsonnet";
local kibana = import "../components/kibana.jsonnet";
local grafana = import "../components/grafana.jsonnet";

/*
 * BKPR on OKE
 *
 * Grant cluster role admin to the API user
 *   $ kubectl create clusterrolebinding <my-cluster-admin-binding> --clusterrole=cluster-admin --user=<user_OCID>
 *
 * like:
 *
 *   $ kubectl create clusterrolebinding admin --clusterrole=cluster-admin --user=$(awk -F "=" '/user/ {print $2}' ~/.oci/config)
 *
 * 1. Create a user named `felipe-oke-bkpr-external-dns` for External
 *    DNS integration.
 * 2. Create a private/public RSA key pair locally. The public key will be
 *    added in PEM format to this `felipe-oke-bkpr-external-dns` user. The
 *    private key is added to the `auth.key` attribute in the `auth_config`
 *    ConfigMap below.
 * 3. Create a group named `felipe-oke-bkpr-external-dns` for External DNS
 *    integration, and add user `felipe-oke-bkpr-external-dns` user to it.
 * 4. Create a compartment named `felipe-oke-bkpr`.
 * 5. Create a DNS zone under Edge -> DNS Zone Management named like
 *    `oke.felipe-alfaro.com` in the `felipe-oke-bkpr` compartment.
 * 6. Create a policy named `external-dns` with the following statement
 *      `Allow group felipe-oke-bkpr-external-dns to manage dns in compartment felipe-oke-bkpr`
 *    inside the `felipe-oke-bkpr` compartment.
 */

{
  config:: error "no kubeprod configuration",

  // Shared metadata for all components
  kubeprod: kube.Namespace("kubeprod"),

  external_dns_zone_name:: $.config.dnsZone,
  letsencrypt_contact_email:: $.config.contactEmail,
  letsencrypt_environment:: "prod",

  version: version,

  // grafana: grafana {
  //   prometheus:: $.prometheus.prometheus.svc,
  //   ingress+: {
  //     host: "grafana." + $.external_dns_zone_name,
  //   },
  // },

  // https://github.com/kubernetes-incubator/external-dns/blob/master/docs/tutorials/oracle.md
  /* NOTES: Integration between ExternalDNS and OCI requires the following:
   *
   *   auth:
   *     region: us-phoenix-1
   *     tenancy: ocid1.tenancy.oc1...
   *     user: ocid1.user.oc1...
   *     key: |
   *       -----BEGIN RSA PRIVATE KEY-----
   *       -----END RSA PRIVATE KEY-----
   *     fingerprint: af:81:71:8e...
   *   compartment: ocid1.compartment.oc1...
   *
   * This means creating a user that has privileges to access the DNS Zone under OCI, which
   * is in the same compartment and tenant.
   *
   */
  edns: edns {
    local this = self,

    // NOTE: OCI/OKE requires a specific user for managing the DNS zone, whose OCID is specified
    // in the `user` attribute. In addition, this user is added to a group, which is required to
    // set up a policy that limits access to the DNS zone.
    auth_config: utils.HashedSecret(this.p + "external-dns-auth") {
      metadata+: {
        namespace: $.kubeprod.metadata.name,
      },
      data_+: {
        _config:: $.config.externalDns,
        "oci.yaml": kubecfg.manifestYaml(self._config),
      },
    },

    deploy+: {
      ownerId: $.external_dns_zone_name,
      spec+: {
        template+: {
          spec+: {
            volumes_+: {
              auth_config: kube.SecretVolume($.edns.auth_config),
            },
            containers_+: {
              edns+: {
                args_+: {
                  provider: "oci",
                },
                volumeMounts_+: {
                  auth_config: {
                    mountPath: "/etc/kubernetes",
                    readOnly: true,
                  },
                },
              },
            },
          },
        },
      },
    },
  },

  cert_manager: cert_manager {
    letsencrypt_contact_email:: $.letsencrypt_contact_email,
    letsencrypt_environment:: $.letsencrypt_environment,
  },

  nginx_ingress: nginx_ingress {
  },

  //   svc+: {
  //     local this = self,
  //     metadata+: {
  //       annotations+: {
  //         "service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled": "true",
  //         "service.beta.kubernetes.io/aws-load-balancer-connection-draining-timeout": std.toString(this.target_pod.spec.terminationGracePeriodSeconds),
  //         // Use PROXY protocol (nginx supports this too)
  //         "service.beta.kubernetes.io/aws-load-balancer-proxy-protocol": "*",
  //       },
  //     },
  //   },
  // },

  oauth2_proxy: oauth2_proxy {
    secret+: {
      data_+: $.config.oauthProxy,
    },

    ingress+: {
      host: "auth." + $.external_dns_zone_name,
    },

    deploy+: {
      spec+: {
        template+: {
          spec+: {
            containers_+: {
              proxy+: {
                args_+: {
                  provider: "oidc",
                  "oidc-issuer-url": "https://cognito-idp.%s.amazonaws.com/%s" % [
                    $.config.oauthProxy.aws_region,
                    $.config.oauthProxy.aws_user_pool_id,
                  ],
                  /* NOTE: disable cookie refresh token.
                   * As per https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html:
                   * The refresh token is defined in the specification, but is not currently implemented to
                   * be returned from the Token Endpoint.
                   */
                  "cookie-refresh": "0",
                },
              },
            },
          },
        },
      },
    },
  },

  // prometheus: prometheus {
  //   ingress+: {
  //     host: "prometheus." + $.external_dns_zone_name,
  //   },
  // },

  // fluentd_es: fluentd_es {
  //   es:: $.elasticsearch,
  // },

  // elasticsearch: elasticsearch,

  // kibana: kibana {
  //   es:: $.elasticsearch,
  //   ingress+: {
  //     host: "kibana." + $.external_dns_zone_name,
  //   },
  // },
}
