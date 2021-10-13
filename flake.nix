{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs";

  description = "Unu niks-floko por servilo de Obscurative";

  outputs = en@{ self, nixpkgs, ... }:
    let
      adminEmail = "guardspirit@protonmail.com";
      domain = "dev.obscurative.ru";
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
            ({ pkgs, config, ... }:
              let
                atest = config.security.acme.certs.ssl.directory;
                atestSxl = "${atest}/key.pem";
                atestDos = "${atest}/cert.pem";
              in {
                boot.isContainer = !digitalOcean;
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
                environment.systemPackages = with pkgs; [ git htop ];
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
                  config = {
                    "Peers" = [ "tcp://94.130.203.208:5999" ];
                    #"Listen" = [ "tls://[::]:0" ];
                  };
                  persistentKeys = true;
                };
                networking.firewall.allowedTCPPorts = [ 443 80 ];

                # Fakta servilo
                security.acme.acceptTerms = true;
                security.acme.email = adminEmail;
                security.acme.certs.ssl = {
                  domain = "${domain}";
                  extraDomainNames = [ "*.${domain}" ];
                  dnsProvider = "digitalocean";
                  credentialsFile = "/root/token";
                  group = config.services.httpd.group;
                };
                services.httpd.adminAddr = adminEmail;
                services.postfix = {
                  enable = true; # Email
                  sslCert = atestDos;
                  sslKey = atestSxl;
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
                          sslServerKey = atestSxl;
                          sslServerCert = atestDos;
                          sslServerChain = "${atest}/chain.pem";
                          listen = [
                            {
                              ip = "200:9b1e:3f34:7257:8a9b:5e6d:2fc2:658f";
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
                      ag = "0750 wordpress ${group} - -";
                    in [
                      "d '${dos}/plugins' ${ag}"
                      "Z '${dos}/plugins' ${ag}"
                      "d '${dos}/themes' ${ag}"
                      "Z '${dos}/themes' ${ag}"
                    ]) subdomains);

              })
          ];
      };
    };
}
