# Local Development Support

```
bundle install


bundle exec ruby setup.rb

source ./env.sh

bundle exec ruby service.rb -p 3001 &
RUST_LOG=debug cargo run &
```

http://service.lo.nkmiusercontent.com:3001 (resolves to localhost)

## Test Fastly CE

```
ECAMO_BIND=127.0.0.1:3002 RUST_LOG=debug cargo run &
FASTLY=1 bundle exec ruby service.rb -p 3001 &
```

```
fastly compute serve --addr=127.0.0.1:3000
```
