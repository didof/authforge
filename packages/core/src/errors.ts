export class AuthForgeError extends Error {
  public override name: string = "AuthForgeError";

  constructor(message: string) {
    super(message);
  }
}

export class ConfigurationError extends AuthForgeError {
  public override name = "ConfigurationError";
}

export class StorageError extends AuthForgeError {
  public override name = "StorageError";
}
