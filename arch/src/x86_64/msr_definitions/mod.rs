pub mod intel;

/// The register address of an MSR
pub struct RegisterAddress(pub u32);

/// Describes a policy for how the corresponding MSR data should be considered when building
/// a CPU profile.
///
/// This is the MSR analogue of [cpuid_definitions::ProfilePolicy](crate::x86_64::cpuid_definitions::ProfilePolicy)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ProfilePolicy {
    /// Store the corresponding data when building the CPU profile.
    ///
    /// When the CPU profile gets utilized the corresponding data will be set into the modified
    /// MSR(s)
    Inherit,
    /// Ignore the corresponding data when building the CPU profile.
    ///
    /// When the CPU profile gets utilized the corresponding data will then instead get
    /// extracted from the host.
    ///
    /// This variant is typically set for data that has no effect on migration compatibility,
    /// but there may be some exceptions such as data which is necessary to run the VM at all,
    /// but must coincide with whatever is on the host.
    Passthrough,
    /// Set the following hardcoded value in the CPU profile.
    ///
    /// This variant is typically used for features/values that don't work well with live migration (even when using the exact same physical CPU model).
    Static(u64),
    /// Deny read and write accesses to this MSR.
    ///
    /// This can only be applied to an MSR in its entirety and not to individual bit ranges
    Deny,
}

/// A description of a range of bits in an MSR.
///
/// This is the MSR analogue of [cpuid_definitions::ValueDefinition](crate::x86_64::cpuid_definitions::ValueDefinition)
#[derive(Clone, Copy, Debug)]
pub struct ValueDefinition {
    /// A short name for the value.
    pub short: &'static str,
    /// A description of the value.
    pub description: &'static str,
    /// The range of bits in the MSR corresponding to this feature or value.
    ///
    /// This is not a `RangeInclusive<u8>` because that type does unfortunately not implement `Copy`.
    pub bits_range: (u8, u8),
    /// The policy corresponding to this value when building CPU profiles.
    pub policy: ProfilePolicy,
}

/// Describes values within an MSR.
///
/// NOTE: The only way to interact with this value (beyond this crate) is via the const [`Self::as_slice()`](Self::as_slice) method.
///
/// This is the MSR analogue of [cpuid_definitions::ValueDefinitions](crate::x86_64::cpuid_definitions::ValueDefinitions)
pub struct ValueDefinitions(&'static [ValueDefinition]);
impl ValueDefinitions {
    /// Constructor permitting at most 64 entries.
    const fn new(msr_descriptions: &'static [ValueDefinition]) -> Self {
        // Note that this function is only called within this module, at compile time, hence it is fine to have some
        // additional sanity checks such as the following assert.
        assert!(msr_descriptions.len() <= 64);
        Self(msr_descriptions)
    }
    /// Converts this into a slice representation. This is the only way to read values of this type.
    pub const fn as_slice(&self) -> &'static [ValueDefinition] {
        self.0
    }
}

/// Describes multiple MSRs.
///
/// Each wrapped [`ValueDefinitions`] corresponds to the given [`RegisterAddress`] in the same tuple.
pub struct MsrDefinitions<const NUM: usize>([(RegisterAddress, ValueDefinitions); NUM]);

impl<const NUM: usize> MsrDefinitions<NUM> {
    pub const fn as_slice(&self) -> &[(RegisterAddress, ValueDefinitions); NUM] {
        &self.0
    }
}
