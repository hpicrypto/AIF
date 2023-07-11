FROM node:16

# Set the number of executions; default is 100
ENV BENCHMARK_COUNT=100
# Use optimized proofs (AIF_ZKP only); default is 0
ENV OPTIMIZED_PROOFS=0
# Dev-flag that excludes all RSA operations; default is 0
ENV WITHOUT_RSA=0

ADD src /app/src
ADD tests /app/tests
ADD package.json /app/package.json
WORKDIR /app
RUN npm install