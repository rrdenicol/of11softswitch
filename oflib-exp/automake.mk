noinst_LIBRARIES += oflib-exp/liboflib_exp.a

oflib_exp_liboflib_exp_a_SOURCES = \
	oflib-exp/ofl-exp.c \
	oflib-exp/ofl-exp.h \
	oflib-exp/ofl-exp-msg-nicira.c \
	oflib-exp/ofl-exp-msg-nicira.h \
	oflib-exp/ofl-exp-match-nicira.c \
        oflib-exp/ofl-exp-match-nicira.h \
        oflib-exp/ofl-exp-openflow.c \
	oflib-exp/ofl-exp-openflow.h \
        oflib-exp/ofl-exp-action-nicira.c \
        oflib-exp/ofl-exp-action-nicira.c


AM_CPPFLAGS += -DOFL_LOG_VLOG
