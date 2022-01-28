{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  description = "Unu niks-floko por servilo de Obscurative";

  outputs = en@{ self, nixpkgs, ... }:
    let
      adminEmail = "guardspirit@protonmail.com";
      domain = "obscurative.ru";
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
                system.stateVersion = "22.05";

                atest = config.security.acme.certs.ssl.directory;
                atestSxl = "${config.atest}/key.pem";
                atestDos = "${config.atest}/cert.pem";

                # Niks
                nix.package = pkgs.nixFlakes;
                nix.extraOptions =
                  "experimental-features = nix-command flakes";
                nix.autoOptimiseStore = true;

                # Masxino
                networking.hostName = "obs";
                system.configurationRevision =
                  nixpkgs.lib.mkIf (self ? rev) self.rev;
                swapDevices = [{
                  device = "/swapfile";
                  size = 3 * 1024; # MB
                }];
                zramSwap = {
                  enable = true;
                  priority = 7;
                  memoryPercent = 75;
                };

                # Medio
                environment.systemPackages = with pkgs; [
                  git
                  htop
                  matrix-appservice-discord
                  du-dust
                ];
                users.defaultUserShell = pkgs.fish;
                programs.fish.enable = true;

                # Sekureco
                boot.kernelPackages = pkgs.linuxPackages_hardened;
                security.sudo.enable = false;
                security.apparmor.enable = true;
                security.lockKernelModules = true;
                security.protectKernelImage = true;
                security.auditd.enable = true;
                services.rsyslogd.enable = true;
                security.audit.enable = true;
                security.audit.rules = [
                  "-a exit,always -F arch=b64 -S execve"
                ];

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
                security.acme.defaults.email = adminEmail;
                security.acme.certs.ssl = {
                  inherit domain;
                  extraDomainNames = [ "*.${domain}" "www.patagona.${domain}" ]; # matrix
                  dnsProvider = "digitalocean";
                  credentialsFile = "/secrets/digitalocean-token";
                };
                #services.httpd.adminAddr = adminEmail;
                #services.postfix = {
                #  enable = true; # Email
                #  sslCert = config.atestDos;
                #  sslKey = config.atestSxl;
                #  hostname = domain;
                #  inherit domain;
                #  config = let milt = config.services.opendkim.socket;
                #  in {
                #    inet_protocols = "ipv4";
                #    milter_default_action = "accept";
                #    milter_protocol = "2";
                #    smtpd_milters = milt;
                #    non_smtpd_milters = milt;
                #  };
                #};
                #services.opendkim = {
                #  enable = true;
                #  selector = "s1";
                #  user = config.services.postfix.user;
                #  domains = "csl:${domain},*.${domain}";
                #};

                #services.wordpress.sites = builtins.listToAttrs (builtins.map
                #  (({ subd, prefix }:
                #    let rdomain = "${subd}${domain}";
                #    in {
                #      name = rdomain;
                #      value = {
                #        virtualHost = {
                #          serverAliases = [ "www.${rdomain}" ];
                #          sslServerKey = config.atestSxl;
                #          sslServerCert = config.atestDos;
                #          sslServerChain = "${config.atest}/chain.pem";
                #          listen = [
                #            {
                #              ip = "202:361:fa33:474d:3a1d:ba05:db60:fb00g";
                #              port = 80;
                #            }
                #            {
                #              ip = "0.0.0.0";
                #              port = 443;
                #              ssl = true;
                #            }
                #          ];
                #        };

                #        database.tablePrefix = "${prefix}_";
                #        contentDir = "/var/lib/wordpress/${rdomain}/content";

                #        extraConfig = ''
                #          define( 'FS_METHOD', 'direct' );
                #          define( 'CUSTOM_USER_TABLE', "users" );
                #        '';
                #      };
                #    })) subdomains);

                #systemd.tmpfiles.rules =
                #  let group = config.services.httpd.group;
                #  in pkgs.lib.lists.flatten (builtins.map ({ subd, ... }:
                #    let
                #      dos = "/var/lib/wordpress/${subd}${domain}/content";
                #      ag = "0750 - ${group} - -";
                #    in [
                #      "d '${dos}/plugins' ${ag}"
                #      "Z '${dos}/plugins' ${ag}"
                #      "d '${dos}/themes' ${ag}"
                #      "Z '${dos}/themes' ${ag}"
                #    ]) subdomains);
              };
            })
            ({ pkgs, config, ... }:
              let
                apps_discord = "/var/lib/matrix-appservice-discord";
                apps_discord_reg = "${apps_discord}/discord-registration.yaml";
              in {
                services.matrix-synapse = {
                  enable = true;
                  settings = {
                    url_preview_enabled = true;
                    allow_guest_access = true;
                    tls_certificate_path = config.atestDos;
                    tls_private_key_path = config.atestSxl;
                    public_baseurl = "https://${matrix}:8448/";
                    listeners = [{
                      bind_addresses = [ "0.0.0.0" ];
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
                    server_name = matrix;
                    enable_registration = true;
                    app_service_config_files = [ "/secrets/discord-tmp.yaml" ];
                  };
                  withJemalloc = true;
                  extraConfigFiles = [ "/secrets/matrix-github-oidc" ];
                };

                users.users.matrix-synapse.extraGroups = [ "acme" ];

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
              })
          ];
      };
    };
}
