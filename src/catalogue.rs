use serde::Deserialize;
use std::collections::HashMap;

/// Un argument de template tel que stocké dans catalogue_dump.json.
/// Les clés sont en MAJUSCULES (format CmdSender.py / nos3_adapter.py).
#[derive(Deserialize, Debug, Clone)]
pub struct CatalogueArg {
    #[serde(rename = "NAME")]
    pub name:       String,
    /// Type CmdSender : "UINT", "INT", "FLOAT", "STRING", "BLOCK"
    #[serde(rename = "TYPE")]
    pub type_name:  String,
    /// Taille en bits, sous forme de string (ex: "16", "8")
    #[serde(rename = "SIZE")]
    pub size:       String,
    /// Valeur par défaut (ex: "0x1806", "0", "\"\"")
    #[serde(rename = "VALUE")]
    pub value:      String,
    /// "BIG_ENDIAN", "LITTLE_ENDIAN" ou "" (= défaut du target)
    #[serde(rename = "ENDIANNESS")]
    pub endianness: String,
}

/// Un template TC complet tel que stocké dans catalogue_dump.json.
/// Les champs `app`, `stateless` sont lus du JSON et disponibles pour
/// filtrage futur (par app, stateless-only).
#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
pub struct CatalogueEntry {
    pub port:      u16,
    /// "CFS" → endianness little-endian par défaut dans CmdSender.py
    pub target:    String,
    pub args:      Vec<CatalogueArg>,
    pub app:       String,
    /// true = la commande peut être envoyée dans n'importe quel état système
    pub stateless: bool,
}

/// Le catalogue complet : TC_NAME → CatalogueEntry (315 TC pour NOS3 v1.6.2)
pub type Catalogue = HashMap<String, CatalogueEntry>;

/// Filtre le catalogue selon la config de campagne.
/// mode = All → aucun filtre.
/// mode = SingleApp | MultiApp → garde seulement les TC dont l'app est dans config.apps.
pub fn filter(cat: Catalogue, config: &crate::config::FuzzConfig) -> Catalogue {
    use crate::config::FuzzMode;

    cat.into_iter()
        .filter(|(_, entry)| {
            // Filtre par app uniquement pour single_app et multi_app.
            // All, CrossApp, Naive et Stateful utilisent tout le catalogue.
            let apply_app_filter = matches!(config.mode, FuzzMode::SingleApp | FuzzMode::MultiApp)
                && !config.apps.is_empty();
            !apply_app_filter || config.apps.contains(&entry.app)
        })
        .collect()
}

/// Charge le catalogue depuis un fichier JSON produit par dump_catalogue.py.
/// Panics avec un message clair si le fichier est absent ou malformé.
pub fn load(path: &str) -> Catalogue {
    let json = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!(
            "Impossible de lire {path}: {e}\n\
             → Générer le catalogue avec : python3 dump_catalogue.py"
        ));
    serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("JSON invalide dans {path}: {e}"))
}
