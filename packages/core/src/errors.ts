export class AeonKeyError extends Error {
  public override name: string = "AeonKeyError";

  constructor(message: string) {
    super(message);
  }
}

export class ConfigurationError extends AeonKeyError {
  public override name = "ConfigurationError";
}

export class StorageError extends AeonKeyError {
  public override name = "StorageError";
}
