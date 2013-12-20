SHELL = /bin/bash
libdir = /usr/lib
PURPLE_MAJOR_VERSION = 2
libpurple_dir = ./libpurple/
libsms_la_OBJECTS = smsprpl.lo udp.lo protocol.lo json.lo buffer.lo aes.lo sha1.lo padlock.lo
LTLIBRARIES = libsms.la
pkg_LTLIBRARIES = libsms.la
MKDIR_P = /bin/mkdir -p
INSTALL = /usr/bin/install -c
pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

CC = gcc
CCLD = $(CC)
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
INCLUDES = -I. -I$(libpurple_dir) -I./crypt/
V_CC = @echo "  CC    " $@;
V_CCLD = @echo "  CCLD  " $@;
V_at = @
mv = mv -f
GLIB_LIBS = -Wl,--export-dynamic -pthread -lgobject-2.0 -lgmodule-2.0 -lgthread-2.0 -lrt -lglib-2.0  
GLIB_CFLAGS = -pthread -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include  
DEBUG_CFLAGS = -Wall  -DPURPLE_DISABLE_DEPRECATED -DPIDGIN_DISABLE_DEPRECATED -DFINCH_DISABLE_DEPRECATED -DGNT_DISABLE_DEPRECATED -Waggregate-return -Wcast-align -Wdeclaration-after-statement -Wendif-labels -Werror-implicit-function-declaration -Wextra -Wno-sign-compare -Wno-unused-parameter -Wformat-security -Werror=format-security -Winit-self -Wmissing-declarations -Wmissing-noreturn -Wmissing-prototypes -Wpointer-arith -Wundef -Wp,-D_FORTIFY_SOURCE=2
libsms_la_LDFLAGS = -module -avoid-version
libsms_la_LIBADD = $(GLIB_LIBS)
LIBS = -lm -lnsl -lresolv 
strip_dir = f=`echo $$p | sed -e 's|^.*/||'`;

CPPFLAGS = $(GLIB_CFLAGS) \
		   $(DEBUG_CFLAGS)
CFLAGS = -g -g -O2
LIBTOOL = $(SHELL) $(libpurple_dir)/libtool --silent
LTCOMPILE = $(LIBTOOL)  --tag=CC $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) \
			$(INCLUDES)  $(CPPFLAGS) $(CFLAGS)

libsms_la_LINK = $(LIBTOOL)  --tag=CC $(LIBTOOLFLAGS) --mode=link $(CCLD) $(CFLAGS) \
	$(libsms_la_LDFLAGS) $(LDFLAGS) -o $@

all: Makefile $(LTLIBRARIES)

libsms.la: $(libsms_la_OBJECTS) 
			$(V_CCLD)$(libsms_la_LINK) -rpath $(pkgdir) $(libsms_la_OBJECTS) $(libsms_la_LIBADD) $(LIBS)

%.lo: %.c
	$(V_CC)$(LTCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(V_at)$(mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Plo

%.lo: crypt/%.c
	$(V_CC)$(LTCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(V_at)$(mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Plo

install: all
	@$(MAKE) $(AM_MAKEFLAGS) install-pkgLTLIBRARIES

install-pkgLTLIBRARIES: $(pkg_LTLIBRARIES)
	@$(NORMAL_INSTALL)
	@list='$(pkg_LTLIBRARIES)'; test -n "$(pkgdir)" || list=; \
	list2=; for p in $$list; do \
	  if test -f $$p; then \
	    list2="$$list2 $$p"; \
	  else :; fi; \
	done; \
	test -z "$$list2" || { \
	  echo " $(MKDIR_P) '$(DESTDIR)$(pkgdir)'"; \
	  $(MKDIR_P) "$(DESTDIR)$(pkgdir)" || exit 1; \
	  echo " $(LIBTOOL)  $(LIBTOOLFLAGS) --mode=install $(INSTALL) $(INSTALL_STRIP_FLAG) $$list2 '$(DESTDIR)$(pkgdir)'"; \
	  $(LIBTOOL)  $(LIBTOOLFLAGS) --mode=install $(INSTALL) $(INSTALL_STRIP_FLAG) $$list2 "$(DESTDIR)$(pkgdir)"; \
	}

clean: clean-libtool clean-pkgLTLIBRARIES

clean-libtool:
	-rm -rf .libs _libs *.lo

clean-pkgLTLIBRARIES:
	-test -z "$(pkg_LTLIBRARIES)" || rm -f $(pkg_LTLIBRARIES)
	@list='$(pkg_LTLIBRARIES)'; for p in $$list; do \
	  dir="`echo $$p | sed -e 's|/[^/]*$$||'`"; \
	  test "$$dir" != "$$p" || dir=.; \
	  echo "rm -f \"$${dir}/so_locations\""; \
	  rm -f "$${dir}/so_locations"; \
	done

uninstall: uninstall-pkgLTLIBRARIES

uninstall-pkgLTLIBRARIES:
	@$(NORMAL_UNINSTALL)
	@list='$(pkg_LTLIBRARIES)'; test -n "$(pkgdir)" || list=; \
	for p in $$list; do \
	  $(strip_dir) \
	  echo " $(LIBTOOL)  $(LIBTOOLFLAGS) --mode=uninstall rm -f '$(DESTDIR)$(pkgdir)/$$f'"; \
	  $(LIBTOOL)  $(LIBTOOLFLAGS) --mode=uninstall rm -f "$(DESTDIR)$(pkgdir)/$$f"; \
	done

