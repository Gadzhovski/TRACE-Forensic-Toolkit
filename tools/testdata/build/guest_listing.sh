# Sourced by the QEMU guests' init scripts (qemu_guest.py): list_tree DIR
# [LABEL [-xdev]] writes one line per entry below DIR -- what this kernel
# sees, the answer key -- as  type TAB fields TAB LABEL/path:
#   file  <size> <sha256> <mtime>
#   link  <target>
#   dir   (nothing)
TAB=$(printf '\t')
list_tree() {
    base="$1"
    label="${2:-}"
    find "$base" -mindepth 1 ${3:-} | sort | while read path; do
        rel="$label${path#$base}"
        if [ -L "$path" ]; then
            echo "link${TAB}$(readlink "$path")${TAB}$rel"
        elif [ -d "$path" ]; then
            echo "dir${TAB}${TAB}$rel"
        else
            digest=$(sha256sum "$path" | cut -d' ' -f1)
            echo "file${TAB}$(stat -c %s "$path") $digest $(stat -c %Y "$path")${TAB}$rel"
        fi
    done
}
