{
  inputs.nixpkgs.url =
    "github:gardspirito/nixpkgs/mx-puppet-discord"; # "github:NixOS/nixpkgs/nixos-unstable";

  description = "Unu niks-floko por servilo de Obscurative";

  outputs = en@{ self, nixpkgs, ... }:
    let
      adminEmail = "guardspirit@protonmail.com";
      domain = "dev.obscurative.ru";
      matrix = "m.obscurative.ru";
      subdomains = [
        {
          subd = "";
          prefix = "obs";
        }
        {
          subd = "patagona.";
          prefix = "pa";
        }
        #{
        #  subd = "ps.";
        #  prefix = "ps";
        #}
      ];
      digitalOcean = true;
    in {
      nixosConfigurations.obs = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = nixpkgs.lib.optional digitalOcean (import
          "${nixpkgs}/nixos/modules/virtualisation/digital-ocean-image.nix")
          ++ [
            ({ pkgs, ... }: {
              disabledModules = [ "services/web-apps/wordpress.nix" ];
            })
            (let
              font = builtins.readFile
                "${nixpkgs}/nixos/modules/services/web-apps/wordpress.nix";
              tek = builtins.replaceStrings [
                "uploadsDir"
                "# symlink uploads directory"
                "$out/share/wordpress/wp-content/uploads"
                "import ../"
              ] [
                "contentDir"
                "rm -rf $out/share/wordpress/wp-content"
                "$out/share/wordpress/wp-content"
                "import ${nixpkgs}/nixos/modules/services/"
              ] font;
              rez = builtins.toFile "wordpress.nix" tek;
            in rez)
            ({ pkgs, config, ... }: {
              options = with pkgs.lib; {
                atest = mkOption { type = types.path; };
                atestSxl = mkOption { type = types.path; };
                atestDos = mkOption { type = types.path; };
              };

              config = {
                atest = config.security.acme.certs.ssl.directory;
                atestSxl = "${config.atest}/key.pem";
                atestDos = "${config.atest}/cert.pem";

                # Niks
                nix.package = pkgs.nixFlakes;
                nix.extraOptions =
                  "experimental-features = nix-command flakes ca-references";
                nix.autoOptimiseStore = true;

                # Masxino
                networking.hostName = "obs";
                system.configurationRevision =
                  nixpkgs.lib.mkIf (self ? rev) self.rev;
                swapDevices = [{
                  device = "/swapfile";
                  size = 3 * 1024; # MB
                }];

                # Medio
                environment.systemPackages = with pkgs; [
                  git
                  htop
                  matrix-appservice-discord
                ];
                users.defaultUserShell = pkgs.fish;
                programs.fish.enable = true;
                zramSwap.enable = true;
                zramSwap.priority = 7;

                # SSH
                services.fail2ban.enable = true;
                services.openssh = {
                  enable = true;
                  ports = [ 4223 ];
                  banner = "Estu homo, kamarado.";
                };

                # Yggdrasil kaj reto
                services.yggdrasil = {
                  enable = true;
                  config = { "Peers" = [ "tcp://94.130.203.208:5999" ]; };
                  persistentKeys = true;
                };
                networking.firewall.allowedTCPPorts = [ 443 80 8448 ];

                # Fakta servilo
                security.acme.acceptTerms = true;
                security.acme.email = adminEmail;
                security.acme.certs.ssl = {
                  inherit domain;
                  extraDomainNames = [ "*.${domain}" matrix ];
                  dnsProvider = "digitalocean";
                  credentialsFile = "/secrets/digitalocean-token";
                  group = config.services.httpd.group;
                };
                services.httpd.adminAddr = adminEmail;
                services.postfix = {
                  enable = true; # Email
                  sslCert = config.atestDos;
                  sslKey = config.atestSxl;
                  hostname = domain;
                  inherit domain;
                  config = let milt = config.services.opendkim.socket;
                  in {
                    inet_protocols = "ipv4";
                    milter_default_action = "accept";
                    milter_protocol = "2";
                    smtpd_milters = milt;
                    non_smtpd_milters = milt;
                  };
                };
                services.opendkim = {
                  enable = true;
                  selector = "s1";
                  user = config.services.postfix.user;
                  domains = "csl:${domain},*.${domain}";
                };

                services.wordpress.sites = builtins.listToAttrs (builtins.map
                  (({ subd, prefix }:
                    let rdomain = "${subd}${domain}";
                    in {
                      name = rdomain;
                      value = {
                        virtualHost = {
                          serverAliases = [ "www.${rdomain}" ];
                          sslServerKey = config.atestSxl;
                          sslServerCert = config.atestDos;
                          sslServerChain = "${config.atest}/chain.pem";
                          listen = [
                            {
                              ip = "202:361:fa33:474d:3a1d:ba05:db60:fb00";
                              port = 80;
                            }
                            {
                              ip = "0.0.0.0";
                              port = 443;
                              ssl = true;
                            }
                          ];
                        };

                        database.tablePrefix = "${prefix}_";
                        contentDir = "/var/lib/wordpress/${rdomain}/content";

                        extraConfig = ''
                          define( 'FS_METHOD', 'direct' );
                          define( 'CUSTOM_USER_TABLE', "users" );
                        '';
                      };
                    })) subdomains);

                systemd.tmpfiles.rules =
                  let group = config.services.httpd.group;
                  in pkgs.lib.lists.flatten (builtins.map ({ subd, ... }:
                    let
                      dos = "/var/lib/wordpress/${subd}${domain}/content";
                      ag = "0750 - ${group} - -";
                    in [
                      "d '${dos}/plugins' ${ag}"
                      "Z '${dos}/plugins' ${ag}"
                      "d '${dos}/themes' ${ag}"
                      "Z '${dos}/themes' ${ag}"
                    ]) subdomains);
              };
            })
            ({ pkgs, config, ... }:
              let
                apps_discord = "/var/lib/matrix-appservice-discord";
                apps_discord_reg = "${apps_discord}/discord-registration.yaml";
              in {
                services.matrix-synapse = {
                  url_preview_enabled = true;
                  allow_guest_access = true;
                  enable = true;
                  server_name = matrix;
                  public_baseurl = "https://${matrix}:8448/";
                  tls_certificate_path = config.atestDos;
                  tls_private_key_path = config.atestSxl;
                  enable_registration = true;
                  withJemalloc = true;
                  listeners = [{
                    bind_address = "0.0.0.0";
                    port = 8448;
                    resources = [
                      {
                        compress = true;
                        names = [ "client" ];
                      }
                      {
                        compress = false;
                        names = [ "federation" ];
                      }
                    ];
                    tls = true;
                    type = "http";
                  }];
                  extraConfig = ''
                    app_service_config_files:
                      - '/secrets/discord-tmp.yaml'
                      #- '/secrets/discord-puppet-tmp.yaml'
                  '';
                  extraConfigFiles = [ "/secrets/matrix-github-oidc" ];
                };

                users.users.matrix-synapse.extraGroups = [ "wwwrun" ];

                services.postgresql = {
                  enable = true;
                  ensureDatabases = [ "matrix-synapse" ];
                  ensureUsers = [{
                    name = "matrix-synapse";
                    ensurePermissions = {
                      "DATABASE \"matrix-synapse\"" = "ALL PRIVILEGES";
                    };
                  }];
                };

                services.matrix-appservice-discord = {
                  enable = true;
                  settings = {
                    bridge = {
                      domain = matrix;
                      enableSelfServiceBridging = true;
                      homeserverUrl = "https://${matrix}:8448";
                    };
                    database = { filename = "${apps_discord}/discord.db"; };
                  };
                  environmentFile = "/secrets/matrix-appservice-discord-token";
                };

                services.mx-puppet-discord = {
                  enable = false;
                  settings = {
                    bridge = {
                      domain = matrix;
                      homeserverUrl = "https://${matrix}:8448";
                    };

                    database = {
                      filename = "/var/lib/mx-puppet-discord/database.db";
                    };
                    logging = {
                      console = "info";
                      lineDateFormat = "MMM-D HH:mm:ss.SSS";
                    };
                    namePatterns = {
                      group = ":name";
                      room = ":name";
                      user = ":name";
                      userOverride = ":displayname";
                    };
                    presence = {
                      enabled = true;
                      interval = 500;
                    };
                    provisioning = {
                      whitelist = [
                        "@scifyro:matrix\\.org"
                        "@gardspirito:m\\.obscurative\\.ru"
                      ];
                    };
                    relay = {
                      whitelist = [
                        "@scifyro:matrix\\.org"
                        "@gardspirito:m\\.obscurative\\.ru"
                        "@vaflo:matrix\\.org"
                      ];
                    };
                    selfService = {
                      whitelist = [ "@gardspirito:m\\.obscurative\\.ru" ];
                    };
                  };
                };
              })
          ];
      };
    };
}
