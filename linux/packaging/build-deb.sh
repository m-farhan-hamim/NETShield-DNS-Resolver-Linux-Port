#!/usr/bin/env bash
# Builds the NetShield DNS Resolver Debian package.
#
#   linux/packaging/build-deb.sh
#
# Environment (all optional):
#   DEB_VERSION   package version (default: versionName from app/build.gradle.kts)
#   OUT_DIR       where the .deb files go (default: linux/dist)
#   JAVAC         javac binary       (default: javac)
#   JAR           jar binary         (default: jar)
#   JAVAC_FLAGS   extra javac flags  (default: --release 17)
#   SKIP_TESTS=1  skip the unit tests
#
# Output: <OUT_DIR>/netshield-dns_<version>_all.deb and a copy named main.deb.
# Needs: a JDK 17+, dpkg-deb, gzip. No network access, no third-party libraries.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$LINUX/.." && pwd)"

JAVAC="${JAVAC:-javac}"
JAR="${JAR:-jar}"
JAVAC_FLAGS="${JAVAC_FLAGS:---release 17}"
OUT_DIR="${OUT_DIR:-$LINUX/dist}"
PKG=netshield-dns

VERSION="${DEB_VERSION:-}"
if [ -z "$VERSION" ] && [ -f "$REPO/app/build.gradle.kts" ]; then
    VERSION="$(sed -n 's/.*versionName *= *"\([^"]*\)".*/\1/p' "$REPO/app/build.gradle.kts" | head -n1)"
fi
VERSION="${VERSION:-0.0.0}"
# Debian versions must start with a digit (strip a leading "v" from tags like v3.0.0).
VERSION="${VERSION#v}"
case "$VERSION" in
    [0-9]*) ;;
    *) echo "error: version '$VERSION' does not start with a digit" >&2; exit 1 ;;
esac

BUILD="$LINUX/build"
CLASSES="$BUILD/classes"
TESTCLASSES="$BUILD/test-classes"
JARFILE="$BUILD/netshield-dns.jar"
STAGE="$BUILD/pkg"

echo "==> Building $PKG $VERSION"
rm -rf "$BUILD"
mkdir -p "$CLASSES" "$TESTCLASSES" "$OUT_DIR"

echo "==> Compiling"
# shellcheck disable=SC2086
"$JAVAC" $JAVAC_FLAGS -Xlint:all -d "$CLASSES" $(find "$LINUX/src/main" -name '*.java' | sort)

if [ "${SKIP_TESTS:-0}" != "1" ]; then
    echo "==> Running unit tests"
    # shellcheck disable=SC2086
    "$JAVAC" $JAVAC_FLAGS -cp "$CLASSES" -d "$TESTCLASSES" $(find "$LINUX/src/test" -name '*.java' | sort)
    java -cp "$CLASSES:$TESTCLASSES" com.psbdx.netshield.SelfTest
fi

echo "==> Creating jar"
MANIFEST="$BUILD/MANIFEST.MF"
{
    echo "Main-Class: com.psbdx.netshield.Daemon"
    echo "Implementation-Title: NetShield DNS Resolver"
    echo "Implementation-Version: $VERSION"
} > "$MANIFEST"
"$JAR" --create --file "$JARFILE" --manifest "$MANIFEST" --date "2026-01-01T00:00:00Z" -C "$CLASSES" . 2>/dev/null \
    || "$JAR" --create --file "$JARFILE" --manifest "$MANIFEST" -C "$CLASSES" .

echo "==> Staging package tree"
install -d -m 0755 \
    "$STAGE/DEBIAN" \
    "$STAGE/usr/bin" \
    "$STAGE/usr/share/$PKG" \
    "$STAGE/usr/share/doc/$PKG" \
    "$STAGE/usr/share/man/man1" \
    "$STAGE/usr/lib/systemd/system" \
    "$STAGE/etc/netshield"

install -m 0644 "$JARFILE" "$STAGE/usr/share/$PKG/netshield-dns.jar"
install -m 0755 "$HERE/netshield" "$STAGE/usr/bin/netshield"
install -m 0644 "$HERE/systemd/netshield-dns.service" "$STAGE/usr/lib/systemd/system/netshield-dns.service"
for f in netshield.conf rules.conf sources.list trusted.list; do
    install -m 0644 "$HERE/etc/$f" "$STAGE/etc/netshield/$f"
done

gzip -9nc "$HERE/man/netshield.1" > "$STAGE/usr/share/man/man1/netshield.1.gz"
chmod 0644 "$STAGE/usr/share/man/man1/netshield.1.gz"

install -m 0644 "$HERE/debian/copyright" "$STAGE/usr/share/doc/$PKG/copyright"
[ -f "$LINUX/README.md" ] && install -m 0644 "$LINUX/README.md" "$STAGE/usr/share/doc/$PKG/README.md"
DATE="$(date -R -u -d "@${SOURCE_DATE_EPOCH:-$(date +%s)}")"
sed -e "s|@VERSION@|$VERSION|g" -e "s|@DATE@|$DATE|g" "$HERE/debian/changelog.in" \
    | gzip -9n > "$STAGE/usr/share/doc/$PKG/changelog.gz"
chmod 0644 "$STAGE/usr/share/doc/$PKG/changelog.gz"

# conffiles: everything under /etc is a conffile, so upgrades keep the admin's edits.
( cd "$STAGE" && find etc -type f | sort | sed 's|^|/|' ) > "$STAGE/DEBIAN/conffiles"
chmod 0644 "$STAGE/DEBIAN/conffiles"

for s in postinst prerm postrm; do
    install -m 0755 "$HERE/debian/$s" "$STAGE/DEBIAN/$s"
done

SIZE="$(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)"
sed -e "s|@VERSION@|$VERSION|g" -e "s|@SIZE@|$SIZE|g" "$HERE/debian/control.in" > "$STAGE/DEBIAN/control"
chmod 0644 "$STAGE/DEBIAN/control"

echo "==> Building .deb"
DEB="$OUT_DIR/${PKG}_${VERSION}_all.deb"
dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$DEB"
cp -f "$DEB" "$OUT_DIR/main.deb"

echo "==> Done"
dpkg-deb --info "$DEB"
echo
dpkg-deb --contents "$DEB"
echo
ls -l "$OUT_DIR"
