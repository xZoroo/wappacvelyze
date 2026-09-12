// JSON data files are large; typing them as unknown keeps type-checking fast and forces
// an explicit cast at the single place each file is loaded.
declare module "*.json" {
  const value: unknown;
  export default value;
}
