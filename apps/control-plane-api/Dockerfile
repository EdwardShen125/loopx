FROM node:22-alpine
WORKDIR /app

# Copy coordination modules (needed for import)
COPY loopx/control_plane/coordination/*.ts /app/loopx/control_plane/coordination/
COPY loopx/control_plane/effect_program.ts /app/loopx/control_plane/
COPY loopx/control_plane/content_digest.ts /app/loopx/control_plane/

# Copy API service
COPY apps/control-plane-api/package.json apps/control-plane-api/package-lock.json /app/apps/control-plane-api/
COPY apps/control-plane-api/main.ts apps/control-plane-api/auth.ts apps/control-plane-api/dependency.ts apps/control-plane-api/capability.ts /app/apps/control-plane-api/

WORKDIR /app/apps/control-plane-api
RUN npm ci --omit=dev

EXPOSE 18082
CMD ["node", "--experimental-strip-types", "main.ts"]
