use super::*;
use punctuated::Punctuated;

ast_struct! {
    /// Data structure sent to a `proc_macro_derive` macro.
    ///
    /// *This type is available if Syn is built with the `"derive"` feature.*
    pub struct DeriveInput {
        /// Attributes tagged on the whole struct or enum.
        pub attrs: Vec<Attribute>,

        /// Visibility of the struct or enum.
        pub vis: Visibility,

        /// Name of the struct or enum.
        pub ident: Ident,

        /// Generics required to complete the definition.
        pub generics: Generics,

        /// Data within the struct or enum.
        pub data: Data,
    }
}

ast_enum_of_structs! {
    /// The storage of a struct, enum or union data structure.
    ///
    /// *This type is available if Syn is built with the `"derive"` feature.*
    ///
    /// # Syntax tree enum
    ///
    /// This type is a [syntax tree enum].
    ///
    /// [syntax tree enum]: enum.Expr.html#syntax-tree-enums
    pub enum Data {
        /// A struct input to a `proc_macro_derive` macro.
        ///
        /// *This type is available if Syn is built with the `"derive"`
        /// feature.*
        pub Struct(DataStruct {
            pub struct_token: Token![struct],
            pub fields: Fields,
            pub semi_token: Option<Token![;]>,
        }),

        /// An enum input to a `proc_macro_derive` macro.
        ///
        /// *This type is available if Syn is built with the `"derive"`
        /// feature.*
        pub Enum(DataEnum {
            pub enum_token: Token![enum],
            pub brace_token: token::Brace,
            pub variants: Punctuated<Variant, Token![,]>,
        }),

        /// A tagged union input to a `proc_macro_derive` macro.
        ///
        /// *This type is available if Syn is built with the `"derive"`
        /// feature.*
        pub Union(DataUnion {
            pub union_token: Token![union],
            pub fields: FieldsNamed,
        }),
    }

    do_not_generate_to_tokens
}

#[cfg(feature = "parsing")]
pub mod parsing {
    use super::*;

    use parse::{Parse, ParseStream, Result};

    impl Parse for DeriveInput {
        fn parse(input: ParseStream) -> Result<Self> {
            let attrs = input.call(Attribute::parse_outer)?;
            let vis = input.parse::<Visibility>()?;

            let lookahead = input.lookahead1();
            if lookahead.peek(Token![struct]) {
                let struct_token = input.parse::<Token![struct]>()?;
                let ident = input.parse::<Ident>()?;
                let generics = input.parse::<Generics>()?;
                let (where_clause, fields, semi) = data_struct(input)?;
                Ok(DeriveInput {
                    attrs: attrs,
                    vis: vis,
                    ident: ident,
                    generics: Generics {
                        where_clause: where_clause,
                        ..generics
                    },
                    data: Data::Struct(DataStruct {
                        struct_token: struct_token,
                        fields: fields,
                        semi_token: semi,
                    }),
                })
            } else if lookahead.peek(Token![enum]) {
                let enum_token = input.parse::<Token![enum]>()?;
                let ident = input.parse::<Ident>()?;
                let generics = input.parse::<Generics>()?;
                let (where_clause, brace, variants) = data_enum(input)?;
                Ok(DeriveInput {
                    attrs: attrs,
                    vis: vis,
                    ident: ident,
                    generics: Generics {
                        where_clause: where_clause,
                        ..generics
                    },
                    data: Data::Enum(DataEnum {
                        enum_token: enum_token,
                        brace_token: brace,
                        variants: variants,
                    }),
                })
            } else if lookahead.peek(Token![union]) {
                let union_token = input.parse::<Token![union]>()?;
                let ident = input.parse::<Ident>()?;
                let generics = input.parse::<Generics>()?;
                let (where_clause, fields) = data_union(input)?;
                Ok(DeriveInput {
                    attrs: attrs,
                    vis: vis,
                    ident: ident,
                    generics: Generics {
                        where_clause: where_clause,
                        ..generics
                    },
                    data: Data::Union(DataUnion {
                        union_token: union_token,
                        fields: fields,
                    }),
                })
            } else {
                Err(lookahead.error())
            }
        }
    }

    pub fn data_struct(
        input: ParseStream,
    ) -> Result<(Option<WhereClause>, Fields, Option<Token![;]>)> {
        let mut lookahead = input.lookahead1();
        let mut where_clause = None;
        if lookahead.peek(Token![where]) {
            where_clause = Some(input.parse()?);
            lookahead = input.lookahead1();
        }

        if where_clause.is_none() && lookahead.peek(token::Paren) {
            let fields = input.parse()?;

            lookahead = input.lookahead1();
            if lookahead.peek(Token![where]) {
                where_clause = Some(input.parse()?);
                lookahead = input.lookahead1();
            }

            if lookahead.peek(Token![;]) {
                let semi = input.parse()?;
                Ok((where_clause, Fields::Unnamed(fields), Some(semi)))
            } else {
                Err(lookahead.error())
            }
        } else if lookahead.peek(token::Brace) {
            let fields = input.parse()?;
            Ok((where_clause, Fields::Named(fields), None))
        } else if lookahead.peek(Token![;]) {
            let semi = input.parse()?;
            Ok((where_clause, Fields::Unit, Some(semi)))
        } else {
            Err(lookahead.error())
        }
    }

    pub fn data_enum(
        input: ParseStream,
    ) -> Result<(
        Option<WhereClause>,
        token::Brace,
        Punctuated<Variant, Token![,]>,
    )> {
        let where_clause = input.parse()?;

        let content;
        let brace = braced!(content in input);
        let variants = content.parse_terminated(Variant::parse)?;

        Ok((where_clause, brace, variants))
    }

    pub fn data_union(input: ParseStream) -> Result<(Option<WhereClause>, FieldsNamed)> {
        let where_clause = input.parse()?;
        let fields = input.parse()?;
        Ok((where_clause, fields))
    }
}

#[cfg(feature = "printing")]
mod printing {
    use super::*;

    use proc_macro2::TokenStream;
    use quote::ToTokens;

    use attr::FilterAttrs;
    use print::TokensOrDefault;

    impl ToTokens for DeriveInput {
        fn to_tokens(&self, tokens: &mut TokenStream) {
            for attr in self.attrs.outer() {
                attr.to_tokens(tokens);
            }
            self.vis.to_tokens(tokens);
            match self.data {
                Data::Struct(ref d) => d.struct_token.to_tokens(tokens),
                Data::Enum(ref d) => d.enum_token.to_tokens(tokens),
                Data::Union(ref d) => d.union_token.to_tokens(tokens),
            }
            self.ident.to_tokens(tokens);
            self.generics.to_tokens(tokens);
            match self.data {
                Data::Struct(ref data) => match data.fields {
                    Fields::Named(ref fields) => {
                        self.generics.where_clause.to_tokens(tokens);
                        fields.to_tokens(tokens);
                    }
                    Fields::Unnamed(ref fields) => {
                        fields.to_tokens(tokens);
                        self.generics.where_clause.to_tokens(tokens);
                        TokensOrDefault(&data.semi_token).to_tokens(tokens);
                    }
                    Fields::Unit => {
                        self.generics.where_clause.to_tokens(tokens);
                        TokensOrDefault(&data.semi_token).to_tokens(tokens);
                    }
                },
                Data::Enum(ref data) => {
                    self.generics.where_clause.to_tokens(tokens);
                    data.brace_token.surround(tokens, |tokens| {
                        data.variants.to_tokens(tokens);
                    });
                }
                Data::Union(ref data) => {
                    self.generics.where_clause.to_tokens(tokens);
                    data.fields.to_tokens(tokens);
                }
            }
        }
    }
}
