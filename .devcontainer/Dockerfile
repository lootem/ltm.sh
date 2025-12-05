FROM ruby:3.3.10-slim-bookworm

WORKDIR /src/app/

COPY Gemfile .

# Install dependencies
RUN apt update
RUN apt install build-essential -y
RUN gem install jekyll bundler
RUN bundle install

ENTRYPOINT ["bundle", "exec", "jekyll", "serve", "--watch", "--livereload", "--force_polling", "--host", "0.0.0.0"]