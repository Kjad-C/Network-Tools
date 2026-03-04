// Small wrapper that delegates to the built-in features registration.
// Keeps the original call-site `FeatureRegistration.RegisterDefaults(manager)` working.

public static class FeatureRegistration
{
    public static void RegisterDefaults(FeatureManager manager)
    {
        BuiltInFeatureRegistration.RegisterDefaults(manager);
    }
}