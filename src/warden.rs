use std::marker::PhantomData;
use std;

extern crate erased_serde;
extern crate serde;
use erased_serde as ede;
use serde::de;
use serde::ser;

extern crate uuid;
use uuid::Uuid;

pub trait Context: ede::Serialize + de::Deserialize {}
impl<C: ede::Serialize + de::Deserialize> Context for C {}

pub struct Request<C: Context> {
    pub id: Uuid,
    pub subject: String,
    pub resource: String,
    pub action: String,
    pub context: C,
}

#[derive(PartialEq)]
pub enum Effect {
    Allow,
    Deny,
}

pub trait Condition<C: Context> {
    fn allow<CS>(&self, &Policy<C, CS>, &Request<C>) -> bool where CS: Conditions<C>;
}

pub trait Conditions<C: Context>
    : ede::Serialize + de::Deserialize + for<'a> Iterator<Item = &'a Policy<C, Self>>
    {
}


pub struct Policy<C, CS>
    where C: Context,
          CS: Conditions<C>
{
    pub id: Uuid,
    pub description: String,
    pub subjects: Vec<String>,
    pub resources: Vec<String>,
    pub actions: Vec<String>,
    pub effect: Effect,
    pub conditions: CS,
    _context: PhantomData<C>,
}

// todo(omeid): impl error:Error
pub struct Error(String);
pub type Result = std::result::Result<Uuid, Error>;

pub type PolicyIterator<'a, C, CS>
    where C: Context,
          CS: Conditions<C> = &'a Iterator<Item = &'a Policy<C, CS>>;


pub trait PolicyProvider<C, CS>
    where C: Context,
          CS: Conditions<C>
{
    fn add_policy(&self, policy: Policy<C, CS>) -> Result;
    fn subject_policies<'a>(&self,
                            subject: &String,
                            action: &String)
                            -> &Iterator<Item = &'a Policy<C, CS>>;
}


pub struct Warden<C, CS, PP>
    where C: Context,
          CS: Conditions<C>,
          PP: PolicyProvider<C, CS>
{
    _context: PhantomData<C>,
    _conditions: PhantomData<CS>,
    policy_provider: PP,
}

impl<C, CS, PP> Warden<C, CS, PP>
    where C: Context,
          CS: Conditions<C>,
          PP: PolicyProvider<C, CS>
{
    pub fn new(pp: PP) -> Self {
        return Warden {
            policy_provider: pp,
            _context: PhantomData,
            _conditions: PhantomData,
        };
    }

    pub fn request_access(&mut self, req: &Request<C>) -> Effect {

        let mut any = false;

        for p in self.policy_provider.subject_policies(&req.subject, &req.subject) {

            any = true;

            if p.effect == Effect::Deny {
                return Effect::Deny;
            }


            for con in &p.conditions {
                if !con.allow(p, req) {
                    return Effect::Deny;
                }
            }
        }

        return if any { Effect::Deny } else { Effect::Allow };
    }
}
