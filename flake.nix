{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
  };

  description = "Unu niks-floko por servilo de Obscurative";

  outputs = { self, nixpkgs }: {
    nixosConfigurations.obs-gxen = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        (import "${nixpkgs}/nixos/modules/virtualisation/digital-ocean-image.nix")
        ({ pkgs, config, ... }: 
          {
            nix.package = pkgs.nixFlakes;
            nix.extraOptions = ''experimental-features = nix-command flakes ca-references'';
            nix.autoOptimiseStore = true;

            system.configurationRevision = nixpkgs.lib.mkIf (self ? rev) self.rev;

            services.openssh.enable = true;

            networking.hostName = "nixos-obs";
            networking.firewall.allowedTCPPorts = [ 443 80 ];

            environment.systemPackages = with pkgs; [
              git
            ];

            # Fakta servilo
            services.httpd.adminAddr = "guardspirit@protonmail.com";
            services.wordpress.sites."dev.obscurative.ru" = {
              virtualHost.serverAliases = [ "www.dev.obscurative.ru" ];
              virtualHost.enableACME = true;
              virtualHost.forceSSL = true;
            };
          }
        )
      ];
    };
  };
}
