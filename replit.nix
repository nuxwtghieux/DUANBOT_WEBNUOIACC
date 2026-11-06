{ pkgs }: {
  deps = [
    pkgs.python310Full
    pkgs.python310Packages.flask
    pkgs.python310Packages.flask-cors
    pkgs.python310Packages.pycryptodome
    pkgs.python310Packages.requests
  ];
}
