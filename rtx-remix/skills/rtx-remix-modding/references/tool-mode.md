# Driving Remix with the direct tools

Recipes for using the Remix MCP tools. Follow the prerequisites and save/readback requirements in [SKILL.md](../SKILL.md).

## `add_asset_reference`

Add an asset reference (USD/MDL) onto an existing prim.

Attach an asset reference to "<prim_path>".

1. `remix_append_prim_reference_file_path` prim_path="<prim_path>", asset_file_path="<asset_path>". (Skip prim-existence checks — the append surfaces errors.)
2. `remix_get_prim_reference_file_paths` prim_path="<prim_path>"; confirm the new reference is present.

## `replace_model_asset`

Swap the currently-selected 3D model in the viewport with an ingested asset.

Swap the selected model with an ingested asset.

1. `remix_get_available_ingested_assets` asset_type="models".
2. `remix_get_prim_paths` selection=true, prim_types=["models"].
3. From step 1's list, pick the first absolute path containing "<ingested_asset>" (substring OK).
4. `remix_replace_prim_reference_file_path` prim_path=<first entry from step 2>, asset_file_path=<step 3 match>.
