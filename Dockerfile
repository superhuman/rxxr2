FROM ocaml/opam2

RUN sudo apt-get install m4 --yes
RUN opam install dune cohttp cohttp-lwt-unix lwt yojson
ADD --chown=opam code /home/opam/code
RUN cd /home/opam/code; eval $(opam env); dune build http.exe
ENTRYPOINT ["/home/opam/code/_build/default/http.exe"]
