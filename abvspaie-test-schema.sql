--
-- PostgreSQL database dump
--

\restrict Hm8AbFsYPGqjUPL5PyGXEdry8sSXv3w3gq9mmancoOHz9t82rN1Qt3MB0K69yWD

-- Dumped from database version 17.11
-- Dumped by pg_dump version 17.11

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: check_entry_balanced(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.check_entry_balanced() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE diff bigint;
BEGIN
  SELECT COALESCE(SUM(CASE direction WHEN 'debit' THEN amount ELSE -amount END),0)
    INTO diff FROM ledger_lines WHERE entry_id = NEW.entry_id;
  IF diff <> 0 THEN RAISE EXCEPTION 'Ã‰criture % dÃ©sÃ©quilibrÃ©e (%)', NEW.entry_id, diff; END IF;
  RETURN NULL;
END; $$;


--
-- Name: forbid_ledger_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.forbid_ledger_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN RAISE EXCEPTION 'Le ledger est immuable'; END; $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: ledger_lines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ledger_lines (
    id bigint NOT NULL,
    entry_id uuid NOT NULL,
    account_id uuid NOT NULL,
    direction text NOT NULL,
    amount bigint NOT NULL,
    CONSTRAINT ledger_lines_amount_check CHECK ((amount > 0)),
    CONSTRAINT ledger_lines_direction_check CHECK ((direction = ANY (ARRAY['debit'::text, 'credit'::text])))
);


--
-- Name: account_balances; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.account_balances AS
 SELECT account_id,
    sum(
        CASE direction
            WHEN 'credit'::text THEN amount
            ELSE (- amount)
        END) AS balance
   FROM public.ledger_lines
  GROUP BY account_id;


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    merchant_id uuid NOT NULL,
    mode text NOT NULL,
    key_prefix text NOT NULL,
    key_hash text NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT api_keys_mode_check CHECK ((mode = ANY (ARRAY['test'::text, 'live'::text])))
);


--
-- Name: customers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    merchant_id uuid NOT NULL,
    name text NOT NULL,
    email text,
    phone text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT customers_email_check CHECK (((email IS NULL) OR (char_length(email) <= 254))),
    CONSTRAINT customers_name_check CHECK (((char_length(name) >= 2) AND (char_length(name) <= 120))),
    CONSTRAINT customers_phone_check CHECK (((phone IS NULL) OR (char_length(phone) <= 40)))
);


--
-- Name: idempotency_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.idempotency_keys (
    merchant_id uuid NOT NULL,
    key text NOT NULL,
    request_hash text NOT NULL,
    transaction_id uuid,
    response_body jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: journal_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.journal_entries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    transaction_id uuid,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ledger_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ledger_accounts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    merchant_id uuid,
    code text NOT NULL,
    currency character(3) DEFAULT 'XOF'::bpchar NOT NULL
);


--
-- Name: ledger_lines_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ledger_lines_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ledger_lines_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ledger_lines_id_seq OWNED BY public.ledger_lines.id;


--
-- Name: merchants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.merchants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    email text NOT NULL,
    country character(2) NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    supabase_user_id uuid,
    CONSTRAINT merchants_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'suspended'::text])))
);


--
-- Name: payment_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payment_links (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    merchant_id uuid NOT NULL,
    token text NOT NULL,
    title text NOT NULL,
    description text,
    amount bigint NOT NULL,
    currency character(3) DEFAULT 'XOF'::bpchar NOT NULL,
    mode text DEFAULT 'test'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    CONSTRAINT payment_links_amount_check CHECK ((amount >= 100)),
    CONSTRAINT payment_links_mode_check CHECK ((mode = ANY (ARRAY['test'::text, 'live'::text]))),
    CONSTRAINT payment_links_status_check CHECK ((status = ANY (ARRAY['active'::text, 'paid'::text, 'expired'::text, 'cancelled'::text])))
);


--
-- Name: provider_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provider_events (
    id bigint NOT NULL,
    provider text NOT NULL,
    payload jsonb NOT NULL,
    processed boolean DEFAULT false NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: provider_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.provider_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: provider_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.provider_events_id_seq OWNED BY public.provider_events.id;


--
-- Name: support_tickets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.support_tickets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    merchant_id uuid NOT NULL,
    subject text NOT NULL,
    message text NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT support_tickets_message_check CHECK (((char_length(message) >= 10) AND (char_length(message) <= 4000))),
    CONSTRAINT support_tickets_status_check CHECK ((status = ANY (ARRAY['open'::text, 'in_progress'::text, 'closed'::text]))),
    CONSTRAINT support_tickets_subject_check CHECK (((char_length(subject) >= 3) AND (char_length(subject) <= 120)))
);


--
-- Name: test_payout_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.test_payout_items (
    payout_id uuid NOT NULL,
    transaction_id uuid NOT NULL,
    amount numeric(18,2) NOT NULL,
    fee_amount numeric(18,2) NOT NULL,
    CONSTRAINT test_payout_items_amount_check CHECK ((amount >= (0)::numeric)),
    CONSTRAINT test_payout_items_check CHECK ((amount >= fee_amount)),
    CONSTRAINT test_payout_items_fee_amount_check CHECK ((fee_amount >= (0)::numeric))
);


--
-- Name: test_payouts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.test_payouts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    merchant_id uuid NOT NULL,
    currency text NOT NULL,
    gross_amount numeric(18,2) NOT NULL,
    fee_amount numeric(18,2) NOT NULL,
    net_amount numeric(18,2) NOT NULL,
    transaction_count integer NOT NULL,
    status text DEFAULT 'simulated'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT test_payouts_check CHECK ((gross_amount >= fee_amount)),
    CONSTRAINT test_payouts_check1 CHECK (((gross_amount - fee_amount) = net_amount)),
    CONSTRAINT test_payouts_currency_check CHECK (((char_length(currency) >= 3) AND (char_length(currency) <= 8))),
    CONSTRAINT test_payouts_fee_amount_check CHECK ((fee_amount >= (0)::numeric)),
    CONSTRAINT test_payouts_gross_amount_check CHECK ((gross_amount >= (0)::numeric)),
    CONSTRAINT test_payouts_net_amount_check CHECK ((net_amount >= (0)::numeric)),
    CONSTRAINT test_payouts_status_check CHECK ((status = 'simulated'::text)),
    CONSTRAINT test_payouts_transaction_count_check CHECK ((transaction_count > 0))
);


--
-- Name: test_refunds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.test_refunds (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    merchant_id uuid NOT NULL,
    transaction_id uuid NOT NULL,
    amount numeric(18,2) NOT NULL,
    currency text NOT NULL,
    status text DEFAULT 'simulated'::text NOT NULL,
    reference text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT test_refunds_amount_check CHECK ((amount > (0)::numeric)),
    CONSTRAINT test_refunds_currency_check CHECK (((char_length(currency) >= 3) AND (char_length(currency) <= 8))),
    CONSTRAINT test_refunds_status_check CHECK ((status = 'simulated'::text))
);


--
-- Name: transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.transactions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    merchant_id uuid NOT NULL,
    mode text NOT NULL,
    type text NOT NULL,
    status text DEFAULT 'created'::text NOT NULL,
    amount bigint NOT NULL,
    fee bigint DEFAULT 0 NOT NULL,
    currency character(3) DEFAULT 'XOF'::bpchar NOT NULL,
    method text NOT NULL,
    provider text NOT NULL,
    provider_ref text,
    customer_phone text,
    reference text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    failure_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT transactions_amount_check CHECK ((amount > 0)),
    CONSTRAINT transactions_fee_check CHECK ((fee >= 0)),
    CONSTRAINT transactions_mode_check CHECK ((mode = ANY (ARRAY['test'::text, 'live'::text]))),
    CONSTRAINT transactions_status_check CHECK ((status = ANY (ARRAY['created'::text, 'pending'::text, 'succeeded'::text, 'failed'::text, 'expired'::text]))),
    CONSTRAINT transactions_type_check CHECK ((type = ANY (ARRAY['payment'::text, 'payout'::text, 'refund'::text])))
);


--
-- Name: webhook_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_deliveries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    endpoint_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt timestamp with time zone,
    last_status integer,
    delivered_at timestamp with time zone
);


--
-- Name: webhook_endpoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_endpoints (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    merchant_id uuid NOT NULL,
    url text NOT NULL,
    secret text NOT NULL,
    events text[] DEFAULT '{*}'::text[] NOT NULL,
    active boolean DEFAULT true NOT NULL
);


--
-- Name: ledger_lines id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ledger_lines ALTER COLUMN id SET DEFAULT nextval('public.ledger_lines_id_seq'::regclass);


--
-- Name: provider_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_events ALTER COLUMN id SET DEFAULT nextval('public.provider_events_id_seq'::regclass);


--
-- Name: api_keys api_keys_key_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: customers customers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_pkey PRIMARY KEY (id);


--
-- Name: idempotency_keys idempotency_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_pkey PRIMARY KEY (merchant_id, key);


--
-- Name: journal_entries journal_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.journal_entries
    ADD CONSTRAINT journal_entries_pkey PRIMARY KEY (id);


--
-- Name: ledger_accounts ledger_accounts_merchant_id_code_currency_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ledger_accounts
    ADD CONSTRAINT ledger_accounts_merchant_id_code_currency_key UNIQUE (merchant_id, code, currency);


--
-- Name: ledger_accounts ledger_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ledger_accounts
    ADD CONSTRAINT ledger_accounts_pkey PRIMARY KEY (id);


--
-- Name: ledger_lines ledger_lines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ledger_lines
    ADD CONSTRAINT ledger_lines_pkey PRIMARY KEY (id);


--
-- Name: merchants merchants_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.merchants
    ADD CONSTRAINT merchants_email_key UNIQUE (email);


--
-- Name: merchants merchants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.merchants
    ADD CONSTRAINT merchants_pkey PRIMARY KEY (id);


--
-- Name: payment_links payment_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_links
    ADD CONSTRAINT payment_links_pkey PRIMARY KEY (id);


--
-- Name: payment_links payment_links_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_links
    ADD CONSTRAINT payment_links_token_key UNIQUE (token);


--
-- Name: provider_events provider_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provider_events
    ADD CONSTRAINT provider_events_pkey PRIMARY KEY (id);


--
-- Name: support_tickets support_tickets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_tickets
    ADD CONSTRAINT support_tickets_pkey PRIMARY KEY (id);


--
-- Name: test_payout_items test_payout_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_payout_items
    ADD CONSTRAINT test_payout_items_pkey PRIMARY KEY (payout_id, transaction_id);


--
-- Name: test_payout_items test_payout_items_transaction_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_payout_items
    ADD CONSTRAINT test_payout_items_transaction_id_key UNIQUE (transaction_id);


--
-- Name: test_payouts test_payouts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_payouts
    ADD CONSTRAINT test_payouts_pkey PRIMARY KEY (id);


--
-- Name: test_refunds test_refunds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_refunds
    ADD CONSTRAINT test_refunds_pkey PRIMARY KEY (id);


--
-- Name: test_refunds test_refunds_reference_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_refunds
    ADD CONSTRAINT test_refunds_reference_key UNIQUE (reference);


--
-- Name: transactions transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.transactions
    ADD CONSTRAINT transactions_pkey PRIMARY KEY (id);


--
-- Name: transactions transactions_provider_provider_ref_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.transactions
    ADD CONSTRAINT transactions_provider_provider_ref_key UNIQUE (provider, provider_ref);


--
-- Name: webhook_deliveries webhook_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);


--
-- Name: webhook_endpoints webhook_endpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_pkey PRIMARY KEY (id);


--
-- Name: customers_merchant_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX customers_merchant_created_idx ON public.customers USING btree (merchant_id, created_at DESC, id DESC);


--
-- Name: customers_merchant_email_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX customers_merchant_email_unique ON public.customers USING btree (merchant_id, lower(email)) WHERE (email IS NOT NULL);


--
-- Name: idx_merchants_supabase_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_merchants_supabase_user_id ON public.merchants USING btree (supabase_user_id) WHERE (supabase_user_id IS NOT NULL);


--
-- Name: idx_payment_links_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_payment_links_created ON public.payment_links USING btree (created_at DESC);


--
-- Name: idx_payment_links_merchant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_payment_links_merchant ON public.payment_links USING btree (merchant_id);


--
-- Name: ledger_lines_account_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ledger_lines_account_id_idx ON public.ledger_lines USING btree (account_id);


--
-- Name: support_tickets_merchant_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX support_tickets_merchant_created_idx ON public.support_tickets USING btree (merchant_id, created_at DESC, id DESC);


--
-- Name: test_payouts_merchant_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX test_payouts_merchant_created_idx ON public.test_payouts USING btree (merchant_id, created_at DESC, id DESC);


--
-- Name: test_refunds_merchant_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX test_refunds_merchant_created_idx ON public.test_refunds USING btree (merchant_id, created_at DESC, id DESC);


--
-- Name: test_refunds_transaction_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX test_refunds_transaction_idx ON public.test_refunds USING btree (transaction_id);


--
-- Name: transactions_merchant_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX transactions_merchant_id_created_at_idx ON public.transactions USING btree (merchant_id, created_at DESC);


--
-- Name: transactions_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX transactions_status_idx ON public.transactions USING btree (status) WHERE (status = 'pending'::text);


--
-- Name: webhook_deliveries_next_attempt_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_deliveries_next_attempt_idx ON public.webhook_deliveries USING btree (next_attempt) WHERE (delivered_at IS NULL);


--
-- Name: ledger_lines lines_balanced; Type: TRIGGER; Schema: public; Owner: -
--

CREATE CONSTRAINT TRIGGER lines_balanced AFTER INSERT ON public.ledger_lines DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.check_entry_balanced();


--
-- Name: ledger_lines lines_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER lines_immutable BEFORE DELETE OR UPDATE ON public.ledger_lines FOR EACH ROW EXECUTE FUNCTION public.forbid_ledger_mutation();


--
-- Name: api_keys api_keys_merchant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_merchant_id_fkey FOREIGN KEY (merchant_id) REFERENCES public.merchants(id);


--
-- Name: customers customers_merchant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_merchant_id_fkey FOREIGN KEY (merchant_id) REFERENCES public.merchants(id) ON DELETE CASCADE;


--
-- Name: idempotency_keys idempotency_keys_merchant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_merchant_id_fkey FOREIGN KEY (merchant_id) REFERENCES public.merchants(id);


--
-- Name: idempotency_keys idempotency_keys_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_transaction_id_fkey FOREIGN KEY (transaction_id) REFERENCES public.transactions(id);


--
-- Name: journal_entries journal_entries_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.journal_entries
    ADD CONSTRAINT journal_entries_transaction_id_fkey FOREIGN KEY (transaction_id) REFERENCES public.transactions(id);


--
-- Name: ledger_accounts ledger_accounts_merchant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ledger_accounts
    ADD CONSTRAINT ledger_accounts_merchant_id_fkey FOREIGN KEY (merchant_id) REFERENCES public.merchants(id);


--
-- Name: ledger_lines ledger_lines_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ledger_lines
    ADD CONSTRAINT ledger_lines_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.ledger_accounts(id);


--
-- Name: ledger_lines ledger_lines_entry_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ledger_lines
    ADD CONSTRAINT ledger_lines_entry_id_fkey FOREIGN KEY (entry_id) REFERENCES public.journal_entries(id);


--
-- Name: payment_links payment_links_merchant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_links
    ADD CONSTRAINT payment_links_merchant_id_fkey FOREIGN KEY (merchant_id) REFERENCES public.merchants(id);


--
-- Name: support_tickets support_tickets_merchant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.support_tickets
    ADD CONSTRAINT support_tickets_merchant_id_fkey FOREIGN KEY (merchant_id) REFERENCES public.merchants(id) ON DELETE CASCADE;


--
-- Name: test_payout_items test_payout_items_payout_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_payout_items
    ADD CONSTRAINT test_payout_items_payout_id_fkey FOREIGN KEY (payout_id) REFERENCES public.test_payouts(id) ON DELETE CASCADE;


--
-- Name: test_payout_items test_payout_items_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_payout_items
    ADD CONSTRAINT test_payout_items_transaction_id_fkey FOREIGN KEY (transaction_id) REFERENCES public.transactions(id);


--
-- Name: test_payouts test_payouts_merchant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_payouts
    ADD CONSTRAINT test_payouts_merchant_id_fkey FOREIGN KEY (merchant_id) REFERENCES public.merchants(id) ON DELETE CASCADE;


--
-- Name: test_refunds test_refunds_merchant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_refunds
    ADD CONSTRAINT test_refunds_merchant_id_fkey FOREIGN KEY (merchant_id) REFERENCES public.merchants(id) ON DELETE CASCADE;


--
-- Name: test_refunds test_refunds_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.test_refunds
    ADD CONSTRAINT test_refunds_transaction_id_fkey FOREIGN KEY (transaction_id) REFERENCES public.transactions(id);


--
-- Name: transactions transactions_merchant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.transactions
    ADD CONSTRAINT transactions_merchant_id_fkey FOREIGN KEY (merchant_id) REFERENCES public.merchants(id);


--
-- Name: webhook_deliveries webhook_deliveries_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_endpoint_id_fkey FOREIGN KEY (endpoint_id) REFERENCES public.webhook_endpoints(id);


--
-- Name: webhook_endpoints webhook_endpoints_merchant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_merchant_id_fkey FOREIGN KEY (merchant_id) REFERENCES public.merchants(id);


--
-- PostgreSQL database dump complete
--

\unrestrict Hm8AbFsYPGqjUPL5PyGXEdry8sSXv3w3gq9mmancoOHz9t82rN1Qt3MB0K69yWD

