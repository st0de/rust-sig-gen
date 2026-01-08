import os
import subprocess
import shutil
import requests
import json
import tempfile
import toml 

FLAIR_DIR = "flair"          # Path to FLAIR bin directory
OUTPUT_DIR = "output"
CRATES_DIR = "crates"
NUM_TOP = 100                # Top 100 crates

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(CRATES_DIR, exist_ok=True)

def get_top_crates(n=100):
    """Fetch top n crates by all-time downloads using the paginated API."""
    crates = []
    page = 1
    per_page = 100  # Max allowed
    
    while len(crates) < n:
        url = f"https://crates.io/api/v1/crates"
        params = {
            "page": page,
            "per_page": per_page,
            "sort": "downloads"  # All-time downloads
        }
        resp = requests.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
        
        page_crates = [c["id"] for c in data["crates"]]
        crates.extend(page_crates)
        
        if len(page_crates) < per_page or len(crates) >= n:
            break
        
        page += 1
    
    return crates[:n]  # Trim to exactly n

def download_crate(name, version=None):
    """Download crate source and extract."""
    if version is None:
        # Get latest version
        url = f"https://crates.io/api/v1/crates/{name}"
        resp = requests.get(url)
        resp.raise_for_status()
        version = resp.json()["crate"]["max_stable_version"]
    
    download_url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    tar_path = f"{CRATES_DIR}/{name}-{version}.crate"
    resp = requests.get(download_url)
    resp.raise_for_status()
    with open(tar_path, "wb") as f:
        f.write(resp.content)
    
    extract_dir = f"{CRATES_DIR}"
    extract_crate_dir = f"{name}-{version}"
    shutil.unpack_archive(tar_path, extract_dir, "gztar")
    return os.path.join(extract_dir, extract_crate_dir)

def build_as_staticlib(crate_dir):
    """Build crate as staticlib for Linux (default) and Windows MSVC targets.
    Returns list of strings: paths to generated .a and/or .lib files."""
    cargo_toml_path = os.path.join(crate_dir, "Cargo.toml")
    
    with open(cargo_toml_path, "r", encoding="utf-8") as f:
        cargo_data = toml.load(f)
    
    # Force staticlib
    cargo_data.setdefault("lib", {})["crate-type"] = ["staticlib"]
    
    # Add panic = "abort" if not present
    release_profile = cargo_data.setdefault("profile", {}).setdefault("release", {})
    if "panic" not in release_profile:
        release_profile["panic"] = "abort"
    
    with open(cargo_toml_path, "w", encoding="utf-8") as f:
        toml.dump(cargo_data, f)
    
    built_libs = []
    
    try:
        # 1. Default target (Linux -> .a)
        print("  Building default target (Linux ELF)...")
        subprocess.check_call(["cargo", "build", "--release"], cwd=crate_dir)
        
        linux_dir = os.path.join(crate_dir, "target", "release")
        linux_lib = find_static_lib(linux_dir)
        if linux_lib:
            built_libs.append(linux_lib)
        
        # 2. Windows MSVC target (-> .lib)
        print("  Building x86_64-pc-windows-msvc (Windows PE)...")
        subprocess.check_call([
            "cargo", "build", "--release", "--target", "x86_64-pc-windows-msvc"
        ], cwd=crate_dir)
        
        win_dir = os.path.join(crate_dir, "target", "x86_64-pc-windows-msvc", "release")
        print(f"!!!!!!!!!!!!!{win_dir}")
        win_lib = find_static_lib(win_dir)
        if win_lib:
            print(f"!!!!!!!!!!!!!Created {win_lib}")
            built_libs.append(win_lib)
    
    except subprocess.CalledProcessError as e:
        print(f"  Build failed: {e}")
        # Continue with whatever was built successfully
    
    return built_libs  # ← Now returns only [str, str] or [] — no tuples!

def find_static_lib(target_dir):
    if not os.path.isdir(target_dir):
        return None
    for file in os.listdir(target_dir):
        if file.endswith((".a", ".lib")):
            return os.path.join(target_dir, file)
    return None

def generate_pat(static_lib_paths, crate_name):
    
    if isinstance(static_lib_paths, str):
        static_lib_paths = [static_lib_paths]
    
    generated_pats = []
    
    for lib_path in static_lib_paths:
        if not os.path.exists(lib_path):
            print(f"Warning: Static lib not found, skipping: {lib_path}")
            continue
        
        # Detect platform by file extension
        if lib_path.endswith(".a"):
            platform = "linux"
            tool_name = "pelf"
            tool_path = os.path.join(FLAIR_DIR, "pelf")
            suffix = "_linux"
        elif lib_path.endswith(".lib"):
            platform = "windows"
            tool_name = "pcf"
            tool_path = os.path.join(FLAIR_DIR, "pcf")
            suffix = "_win"
        else:
            print(f"Unknown static lib format, skipping: {lib_path}")
            continue
        
        if not os.path.exists(tool_path):
            raise FileNotFoundError(f"Required FLAIR tool not found: {tool_path}")
        
        pat_path = os.path.join(OUTPUT_DIR, f"{crate_name}{suffix}.pat")
        
        print(f"Generating {platform} .pat using {tool_name} → {os.path.basename(pat_path)}")
        try:
            subprocess.check_call([tool_path, lib_path, pat_path])
            if os.path.exists(pat_path):
                generated_pats.append(pat_path)
                print(f"Success: {pat_path}")
            else:
                print(f"Failed: .pat file was not created")
        except subprocess.CalledProcessError as e:
            print(f"Error running {tool_name}: {e}")
    
    return generated_pats

def generate_sig(pat_path, crate_name):
    
    # Determine signature base name from the .pat filename
    sig_base_name = os.path.basename(pat_path[:-4])
    sig_path = os.path.join(OUTPUT_DIR, f"{sig_base_name}.sig")
    exc_path = os.path.join(OUTPUT_DIR, f"{sig_base_name}.exc")
    
    # Choose sigmake based on host OS (optional, but safe)
    sigmake_tool = "sigmake"
    sigmake_path = os.path.join(FLAIR_DIR, sigmake_tool)
    
    if not os.path.exists(sigmake_path):
        raise FileNotFoundError("sigmake not found in FLAIR directory")
    
    print(f"Generating signature: {sig_base_name}.sig")
    
    try:
        subprocess.check_call([sigmake_path, pat_path, sig_path])
    except subprocess.CalledProcessError:
        print(f"  Collisions detected for {sig_base_name}, attempting to resolve...")
        
        if os.path.exists(exc_path):
            # Remove commented lines (common fix for collisions)
            with open(exc_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            with open(exc_path, "w", encoding="utf-8") as f:
                for line in lines:
                    if line.strip() and not line.startswith(";"):
                        f.write(line)
            # Retry
            subprocess.check_call([sigmake_path, pat_path, sig_path])
        else:
            print(f"  No .exc file generated — signature may have too many collisions")
            return None
    
    if os.path.exists(sig_path):
        print(f"  Success: {os.path.basename(sig_path)} created")
        return sig_path
    else:
        print(f"  Failed to create signature")
        return None

def main():
    top_crates = get_top_crates(NUM_TOP)
    print(f"Top {NUM_TOP} crates: {top_crates}")
    
    for name in top_crates:
        print(f"\nProcessing {name}...")

        try:
            crate_dir = download_crate(name)
            lib_paths = build_as_staticlib(crate_dir)  # Returns list[str] of .a and/or .lib paths
            
            if not lib_paths:
                print(f"No static libraries built for {name}")
                continue
            
            # Generate both .pat files (linux + windows if available)
            pat_paths = generate_pat(lib_paths, name)
            
            if not pat_paths:
                print("No .pat files generated")
                continue
            
            # Generate .sig for each .pat
            for pat_path in pat_paths:
                sig_path = generate_sig(pat_path, name)
                if sig_path:
                    print(f"Completed: {os.path.basename(sig_path)}\n")
                
        except Exception as e:
            print(f"Failed for {name}: {e}\n")

if __name__ == "__main__":
    main()
