{ pkgs, ... }: {
  channel = "stable-24.05";

  packages = [
    pkgs.python310
    pkgs.python310Full
    pkgs.python310Packages.pip
    pkgs.python310Packages.virtualenv
    pkgs.gcc  # Optional but useful if any dependencies need compilation
  ];

  env = {
    PYTHONIOENCODING = "utf-8";
    LC_ALL = "en_US.UTF-8";
  };

  idx = {
    extensions = [];

    previews = {
      enable = true;
      previews = {
        # configure preview later if needed
      };
    };

    workspace = {
      onCreate = {
        # optional setup
      };
      onStart = {
        # optional startup tasks
      };
    };
  };
}
